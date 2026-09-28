using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// Feature 3 — Discovers all API route definitions across Express, ASP.NET, Django, and Flask.
/// For each endpoint, checks whether authentication, input validation, and rate limiting are present.
/// Unprotected endpoints are flagged with appropriate severity.
/// </summary>
public static class ApiSurfaceMapper
{
    // ── ROUTE DEFINITION PATTERNS ──
    private static readonly (Regex Rx, string Framework, Func<Match, (string Method, string Route)> Extract)[] RouteRules =
    {
        // Express.js — app.get("/path", ...) / router.post("/path", ...)
        (new Regex(@"(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['""]([^'""]+)['""]", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            "Express.js", m => (m.Groups[1].Value.ToUpper(), m.Groups[2].Value)),

        // ASP.NET — [HttpGet("path")] or [HttpPost]
        (new Regex(@"\[Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*""([^""]*)""\s*\))?\]", RegexOptions.Compiled),
            "ASP.NET", m => (m.Groups[1].Value.ToUpper(), m.Groups[2].Success ? m.Groups[2].Value : "(controller default)")),

        // Django — path("route/", view)
        (new Regex(@"path\s*\(\s*['""]([^'""]+)['""]", RegexOptions.Compiled),
            "Django", m => ("ANY", m.Groups[1].Value)),

        // Flask — @app.route("/path", methods=["POST"])
        (new Regex(@"@\w+\.route\s*\(\s*['""]([^'""]+)['""](?:.*?methods\s*=\s*\[([^\]]+)\])?", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            "Flask", m => (m.Groups[2].Success ? m.Groups[2].Value.Trim('\'', '"', ' ').ToUpper() : "GET", m.Groups[1].Value)),

        // FastAPI — @app.get("/path")
        (new Regex(@"@\w+\.(get|post|put|delete|patch)\s*\(\s*['""]([^'""]+)['""]", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            "FastAPI", m => (m.Groups[1].Value.ToUpper(), m.Groups[2].Value)),
    };

    // ── AUTH DETECTION ──
    private static readonly Regex AuthRx = new(
        @"\b(requireAuth|authenticate|passport\.authenticate|jwt\.verify|verifyToken|isAuthenticated|isLoggedIn|\[Authorize\]|@login_required|permission_required|IsAuthenticated|auth_required|protect|ensureAuth|AuthGuard|RequireAuthorization|UseAuthentication|verifyJWT|checkAuth)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ── INPUT VALIDATION DETECTION ──
    private static readonly Regex ValidationRx = new(
        @"\b(express-validator|joi\.validate|celebrate|validationResult|check\(|body\(|param\(|query\(|\[Required\]|ModelState\.IsValid|FluentValidation|DataAnnotations|form\.is_valid|serializer\.is_valid|@Valid|@Validated|zod\.object|yup\.object)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ── RATE LIMITING DETECTION ──
    private static readonly Regex RateLimitRx = new(
        @"\b(rateLimit|express-rate-limit|rate_limit|throttle|EnableRateLimiting|UseRateLimiter|RateLimiter|@throttle_classes|slowDown|bottleneck)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();
        var endpoints = new List<EndpointInfo>();

        // ── Discover all endpoints ──
        foreach (var file in files)
        {
            for (int i = 0; i < file.Lines.Length; i++)
            {
                var line = file.Lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                foreach (var (rx, framework, extract) in RouteRules)
                {
                    try
                    {
                        var match = rx.Match(line);
                        if (match.Success)
                        {
                            var (method, route) = extract(match);
                            endpoints.Add(new EndpointInfo
                            {
                                Method = method,
                                Route = route,
                                Framework = framework,
                                FilePath = file.FilePath,
                                LineNumber = i + 1
                            });
                        }
                    }
                    catch (RegexMatchTimeoutException) { }
                }
            }
        }

        // ── Analyze each endpoint for protections ──
        foreach (var ep in endpoints)
        {
            var file = files.FirstOrDefault(f => f.FilePath == ep.FilePath);
            if (file == null) continue;

            // Search a window around the route: 30 lines before (middleware/decorators) and 40 after (handler body)
            int ctxStart = Math.Max(0, ep.LineNumber - 30);
            int ctxEnd = Math.Min(file.Lines.Length, ep.LineNumber + 40);
            var context = string.Join("\n", file.Lines[ctxStart..ctxEnd]);

            // Also check full file for global middleware registrations
            ep.HasAuth = AuthRx.IsMatch(context) || HasGlobalMiddleware(file.Content, AuthRx);
            ep.HasValidation = ValidationRx.IsMatch(context);
            ep.HasRateLimit = RateLimitRx.IsMatch(file.Content);

            // ── Flag missing auth (WARNING) ──
            if (!ep.HasAuth)
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Warning",
                    Title = "Unprotected API Endpoint",
                    Description = $"Endpoint {ep.Method} {ep.Route} has no authentication middleware detected.",
                    FilePath = ep.FilePath,
                    LineNumber = ep.LineNumber,
                    Suggestion = $"Add authentication middleware to protect this endpoint. Framework detected: {ep.Framework}.",
                    EffortLevel = "Medium",
                    Category = "ApiSurface",
                    ConfidenceScore = 75
                });
            }

            // ── Flag missing validation (INFO) ──
            if (!ep.HasValidation)
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Info",
                    Title = "No Input Validation on Endpoint",
                    Description = $"Endpoint {ep.Method} {ep.Route} has no input validation detected.",
                    FilePath = ep.FilePath,
                    LineNumber = ep.LineNumber,
                    Suggestion = $"Add input validation middleware to prevent malformed/malicious data. Framework: {ep.Framework}.",
                    EffortLevel = "Easy",
                    Category = "ApiSurface",
                    ConfidenceScore = 50
                });
            }

            // ── Flag missing rate limiting on mutation endpoints (INFO) ──
            if (!ep.HasRateLimit && ep.Method is "POST" or "PUT" or "DELETE" or "PATCH")
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Info",
                    Title = "No Rate Limiting on Mutating Endpoint",
                    Description = $"Endpoint {ep.Method} {ep.Route} has no rate limiting detected.",
                    FilePath = ep.FilePath,
                    LineNumber = ep.LineNumber,
                    Suggestion = "Add rate limiting to prevent abuse and brute-force attacks on this endpoint.",
                    EffortLevel = "Easy",
                    Category = "ApiSurface",
                    ConfidenceScore = 45
                });
            }
        }

        return issues;
    }

    /// <summary>Checks if a global middleware is registered (e.g., app.use(authenticate))</summary>
    private static bool HasGlobalMiddleware(string fullContent, Regex rx)
    {
        // Only count as global if it appears in a use() or services.Add pattern
        return fullContent.Contains("app.use(", StringComparison.OrdinalIgnoreCase) && rx.IsMatch(fullContent);
    }

    private class EndpointInfo
    {
        public string Method { get; set; } = "";
        public string Route { get; set; } = "";
        public string Framework { get; set; } = "";
        public string FilePath { get; set; } = "";
        public int LineNumber { get; set; }
        public bool HasAuth { get; set; }
        public bool HasValidation { get; set; }
        public bool HasRateLimit { get; set; }
    }
}
