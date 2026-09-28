using System.Collections.Concurrent;
using System.Diagnostics;
using CodeSentry.API.Models;
using CodeSentry.API.Services.Analyzers;

namespace CodeSentry.API.Services;

public interface IStaticAnalysisEngine
{
    Task<AnalysisResult> AnalyzeAsync(FileWalkResult walkResult, string repoRoot, IProgress<string>? progress = null, CancellationToken cancellationToken = default);
}

public class StaticAnalysisEngine : IStaticAnalysisEngine
{
    private readonly ILogger<StaticAnalysisEngine> _logger;

    public StaticAnalysisEngine(ILogger<StaticAnalysisEngine> logger)
    {
        _logger = logger;
    }

    public async Task<AnalysisResult> AnalyzeAsync(FileWalkResult walkResult, string repoRoot, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var allIssues = new ConcurrentBag<CodeIssue>();

        void Report(string msg) => progress?.Report(msg);

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 1: PARALLEL STATIC ANALYZERS (regex-based, CPU-bound)
        // ═══════════════════════════════════════════════════════════════════
        Report("[ENGINE] Running parallel static analyzers...");

        var analyzers = new (Func<List<CodeIssue>> Analyzer, string Name)[]
        {
            (() => SecurityAnalyzer.Analyze(walkResult.Files),                       "Security"),
            (() => QualityAnalyzer.Analyze(walkResult.Files),                        "Quality"),
            (() => DependencyAnalyzer.Analyze(walkResult.Files),                     "Dependency"),
            (() => PerformanceAnalyzer.Analyze(walkResult.Files),                    "Performance"),
            (() => SecretsEntropyAnalyzer.Analyze(walkResult.Files),                 "Entropy"),
            (() => StructureAnalyzer.Analyze(walkResult.Files, repoRoot),            "Structure"),
            (() => RepoHygieneAnalyzer.Analyze(walkResult.Files, repoRoot),          "Hygiene"),
            (() => CrossFileDataFlowAnalyzer.Analyze(walkResult.Files),              "DataFlow"),
            (() => ApiSurfaceMapper.Analyze(walkResult.Files),                       "ApiSurface"),
        };

        Parallel.ForEach(analyzers, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = cancellationToken }, pair =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var issues = pair.Analyzer();
                foreach (var issue in issues) allIssues.Add(issue);
                _logger.LogInformation("[ENGINE] {Analyzer}Analyzer found {Count} issues", pair.Name, issues.Count);
            }
            catch (OperationCanceledException)
            {
                // Ignored - will bubble up
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("[ENGINE] {Analyzer}Analyzer failed: {Error}", pair.Name, ex.Message);
            }
        });

        cancellationToken.ThrowIfCancellationRequested();

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 2: GIT HISTORY SECRET SCANNER (async, I/O-bound)
        // ═══════════════════════════════════════════════════════════════════
        Report("[ENGINE] Scanning git history for leaked secrets...");
        try
        {
            var gitHistoryIssues = await GitHistorySecretScanner.AnalyzeAsync(repoRoot);
            foreach (var issue in gitHistoryIssues) allIssues.Add(issue);
            _logger.LogInformation("[ENGINE] GitHistorySecretScanner found {Count} issues", gitHistoryIssues.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[ENGINE] GitHistorySecretScanner failed: {Error}", ex.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 3: DEEP GIT OBJECT FORENSICS (async, I/O-bound)
        // ═══════════════════════════════════════════════════════════════════
        Report("[ENGINE] Running deep git object forensics (unreachable blobs, reflog, stashes, hooks, config)...");
        try
        {
            var gitObjectIssues = await GitObjectScanner.AnalyzeAsync(repoRoot);
            foreach (var issue in gitObjectIssues) allIssues.Add(issue);
            _logger.LogInformation("[ENGINE] GitObjectScanner found {Count} issues", gitObjectIssues.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[ENGINE] GitObjectScanner failed: {Error}", ex.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 4: CONFIDENCE SCORING (post-processing)
        // ═══════════════════════════════════════════════════════════════════
        Report("[ENGINE] Calculating confidence scores and filtering false positives...");
        var issuesList = allIssues.ToList();
        try
        {
            ConfidenceScorer.Score(issuesList, walkResult.Files);
            _logger.LogInformation("[ENGINE] ConfidenceScorer scored {Count} issues", issuesList.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[ENGINE] ConfidenceScorer failed: {Error}", ex.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 5: FORENSIC ATTRIBUTION — git blame every finding
        // ═══════════════════════════════════════════════════════════════════
        Report("[ENGINE] Attributing findings to authors via git blame...");
        try
        {
            await GitAttributionAnalyzer.EnrichAsync(issuesList, repoRoot);
            _logger.LogInformation("[ENGINE] GitAttributionAnalyzer enriched issues with commit metadata");
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[ENGINE] GitAttributionAnalyzer failed: {Error}", ex.Message);
        }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 6: ATTACK CHAIN CORRELATION
        // ═══════════════════════════════════════════════════════════════════
        Report("[ENGINE] Correlating attack chains and reachability...");
        CorrelateAttackChains(issuesList);

        sw.Stop();

        int critCount = issuesList.Count(i => i.Severity == "Critical");
        int warnCount = issuesList.Count(i => i.Severity == "Warning");
        int infoCount = issuesList.Count(i => i.Severity == "Info");

        int score = 100;
        
        // Critical issues carry heavy weight but capped at 40 points total deduction
        int criticalDeduction = Math.Min(40, critCount * 10);
        score -= criticalDeduction;

        // Warnings capped at 30 points total deduction to avoid false-positive cascades
        int warningDeduction = Math.Min(30, warnCount * 3);
        score -= warningDeduction;

        // Informational findings capped at 10 points total deduction
        int infoDeduction = Math.Min(10, infoCount * 1);
        score -= infoDeduction;

        if (!issuesList.Any(i => i.Title == "No Tests Detected")) score += 5;
        if (!issuesList.Any(i => i.Title == "No CI/CD Configuration")) score += 3;
        if (!issuesList.Any(i => i.Title == "No README Found")) score += 2;
        if (!issuesList.Any(i => i.Title == "No .gitignore File")) score += 2;
        if (!issuesList.Any(i => i.Title.Contains("Hardcoded") && i.Severity == "Critical")) score += 5;

        score = Math.Max(5, score);
        score = Math.Min(100, score);

        double debtHours = (critCount * 4.0) + (warnCount * 1.5) + (infoCount * 0.5);
        var summary = BuildSummary(walkResult, issuesList, critCount, warnCount, infoCount, score, debtHours);

        var secVulns = issuesList
            .Where(i => i.Category == "Security" && i.Severity == "Critical")
            .Select(i => i.Title)
            .Distinct()
            .ToList();

        // ── RISK SCORE PER FILE ──
        var fileSummaries = issuesList.GroupBy(i => i.FilePath).Select(g => 
        {
            int crit = g.Count(i => i.Severity == "Critical");
            int warn = g.Count(i => i.Severity == "Warning");
            int info = g.Count(i => i.Severity == "Info");
            
            int riskScore = crit * 10 + warn * 3 + info * 1;
            string riskTier = riskScore >= 30 ? "CRITICAL" : riskScore >= 10 ? "WARNING" : "LOW";
            
            return new FileSummary
            {
                FilePath = g.Key,
                RiskScore = riskScore,
                RiskTier = riskTier,
                CriticalCount = crit,
                WarningCount = warn,
                InfoCount = info
            };
        }).ToList();

        _logger.LogInformation("[ENGINE] Analysis complete — {Count} issues, score {Score}/100, {Ms}ms",
            issuesList.Count, score, sw.ElapsedMilliseconds);

        var result = new AnalysisResult
        {
            HealthScore = score,
            Issues = issuesList,
            SecurityVulnerabilities = secVulns,
            Summary = summary,
            FileSummaries = fileSummaries
        };

        _logger.LogInformation("FileSummaries count: {count}", result.FileSummaries.Count);

        return result;
    }

    private static void CorrelateAttackChains(List<CodeIssue> issues)
    {
        var byFile = issues.GroupBy(i => i.FilePath).ToList();

        foreach (var fileGroup in byFile)
        {
            var fileIssues = fileGroup.ToList();

            var hasUnprotectedApi  = fileIssues.Any(i => i.Title == "Unprotected API Endpoint");
            var hasNoValidation    = fileIssues.Any(i => i.Title == "No Input Validation on Endpoint");

            if (hasUnprotectedApi && hasNoValidation)
            {
                var api = fileIssues.FirstOrDefault(i => i.Title == "Unprotected API Endpoint");
                if (api != null)
                {
                    api.Severity = "Critical";
                    api.Description += " [CHAINED] This endpoint also lacks input validation — direct exploitation path.";
                    api.ConfidenceScore = Math.Min(100, api.ConfidenceScore + 15);
                }
            }

            foreach (var secret in fileIssues.Where(i => i.Title.Contains("Hardcoded") || i.Title.Contains("Secret")))
            {
                if (string.IsNullOrEmpty(secret.ReachabilityStatus))
                    secret.ReachabilityStatus = "Active";
            }

            foreach (var flow in fileIssues.Where(i => i.DataFlowTrace != null && i.Severity == "Warning"))
            {
                flow.Severity = "Critical";
                flow.ConfidenceScore = Math.Min(100, flow.ConfidenceScore + 10);
            }
        }
    }

    private static string BuildSummary(FileWalkResult walk, List<CodeIssue> issues,
        int crit, int warn, int info, int score, double debtHours)
    {
        var parts = new List<string>();
        parts.Add($"Repository scanned: {walk.Files.Count} files, {walk.TotalLines:N0} lines of code analyzed.");

        if (crit > 0)
        {
            var topCrit = issues.FirstOrDefault(i => i.Severity == "Critical");
            if (topCrit != null)
                parts.Add($"{crit} critical vulnerabilities detected — {topCrit.Title} in {topCrit.FilePath} requires immediate attention.");
            else
                parts.Add($"{crit} critical vulnerabilities detected.");
        }

        if (warn > 0)
        {
            var topFile = issues.Where(i => i.Severity == "Warning")
                .GroupBy(i => i.FilePath).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key;
            parts.Add(string.IsNullOrEmpty(topFile)
                ? $"{warn} warnings found."
                : $"{warn} warnings found, primarily in {topFile}.");
        }

        if (info > 0)
            parts.Add($"{info} informational findings noted.");

        var gitHistoryCount = issues.Count(i => i.Title.Contains("Git History", StringComparison.OrdinalIgnoreCase));
        var danglingCount   = issues.Count(i => i.ReachabilityStatus == "DanglingBlob" || i.ReachabilityStatus == "UnreachableCommit");
        var dataFlowCount   = issues.Count(i => i.DataFlowTrace != null);
        var apiSurfaceCount = issues.Count(i => i.Category == "ApiSurface");
        var highConfidence  = issues.Count(i => i.ConfidenceScore >= 80);
        var attributedCount = issues.Count(i => !string.IsNullOrEmpty(i.CommitHash));

        if (gitHistoryCount > 0) parts.Add($"⚠️ {gitHistoryCount} secrets found in git history — still recoverable.");
        if (danglingCount > 0)   parts.Add($"💀 {danglingCount} findings in unreachable/dangling git objects — deep forensic layer.");
        if (dataFlowCount > 0)   parts.Add($"🔗 {dataFlowCount} proven data flow vulnerabilities traced.");
        if (apiSurfaceCount > 0) parts.Add($"🌐 {apiSurfaceCount} API surface findings across discovered endpoints.");

        parts.Add($"✅ Confidence: {highConfidence} high-confidence findings.");

        if (attributedCount > 0)
            parts.Add($"👤 {attributedCount} findings attributed to specific commits via git blame.");

        string label = score >= 80 ? "Healthy" : score >= 50 ? "Needs Attention" : "Critical";
        parts.Add($"Estimated {debtHours:F0}h of technical debt. Overall health: {label} ({score}/100).");

        return string.Join(" ", parts);
    }
}
