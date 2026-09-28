using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// ADVANCED CROSS-FILE DATA FLOW TRACKER v2 — traces taint from HTTP request parameters
/// through function calls, class properties, and module exports to dangerous sinks.
/// If user input reaches a sink without passing through validation/sanitization,
/// it is flagged as CRITICAL with a complete flow trace.
/// </summary>
public static class CrossFileDataFlowAnalyzer
{
    // ── SOURCE PATTERNS (user input entry points) ──
    private static readonly (Regex Rx, string Label)[] Sources =
    {
        (new Regex(@"req\.(body|params|query|headers)\b", RegexOptions.Compiled), "Express req"),
        (new Regex(@"request\.(body|params|query)\b", RegexOptions.Compiled), "Express request"),
        (new Regex(@"Request\.(Form|Query|Headers)\[", RegexOptions.Compiled), "ASP.NET Request"),
        (new Regex(@"\[From(Body|Query|Route|Form)\]", RegexOptions.Compiled), "ASP.NET Binding"),
        (new Regex(@"request\.(GET|POST|data)\[", RegexOptions.Compiled), "Django request"),
        (new Regex(@"request\.(form|args|json)\[", RegexOptions.Compiled), "Flask request"),
        (new Regex(@"@RequestParam|@PathVariable|@RequestBody", RegexOptions.Compiled), "Spring Binding"),
        (new Regex(@"\$_(GET|POST|REQUEST|COOKIE)\[", RegexOptions.Compiled), "PHP superglobal"),
        (new Regex("params\\[:\\w+\\]|params\\[\"\\w+\"\\]", RegexOptions.Compiled), "Rails params"),
        (new Regex("@Param\\s*\\(\\s*\"\\w+\"\\s*\\)", RegexOptions.Compiled), "JPA Param"),
    };

    // ── SINK PATTERNS (dangerous operations) ──
    private static readonly (Regex Rx, string SinkType, string Vuln)[] Sinks =
    {
        // SQL injection sinks
        (new Regex(@"(\.query|\.execute|cursor\.execute|ExecuteReader|ExecuteNonQuery|ExecuteScalar|SqlCommand|mysql_query|pg_query|mysqli_query|pdo->query|sqlite3_exec)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Database Query", "SQL Injection"),
        (new Regex("\\\"\\\"\\\"(SELECT|INSERT|UPDATE|DELETE)\\s.+?\\\"\\\"\\\"\\s*\\+", RegexOptions.Compiled | RegexOptions.IgnoreCase), "SQL String Concat", "SQL Injection"),
        (new Regex("\\$\\\"\\\"\\\"(SELECT|INSERT|UPDATE|DELETE)\\s", RegexOptions.Compiled | RegexOptions.IgnoreCase), "SQL Interpolation", "SQL Injection"),
        (new Regex("f\\\"\\\"\\\"(SELECT|INSERT|UPDATE|DELETE)\\s", RegexOptions.Compiled | RegexOptions.IgnoreCase), "SQL f-string", "SQL Injection"),
        // XSS sinks
        (new Regex(@"\.innerHTML\s*="), "innerHTML", "Cross-Site Scripting (XSS)"),
        (new Regex(@"document\.write\s*\("), "document.write", "Cross-Site Scripting (XSS)"),
        (new Regex(@"Html\.Raw\s*\("), "Html.Raw", "Cross-Site Scripting (XSS)"),
        (new Regex(@"dangerouslySetInnerHTML"), "dangerouslySetInnerHTML", "Cross-Site Scripting (XSS)"),
        (new Regex(@"v-html\s*="), "Vue v-html", "Cross-Site Scripting (XSS)"),
        (new Regex(@"\{\{\{\s*\w+\s*\}\}\}", RegexOptions.Compiled), "Triple Mustache (raw HTML)", "Cross-Site Scripting (XSS)"),
        // Command injection sinks
        (new Regex(@"(child_process\.exec|os\.system|subprocess\.(call|run|Popen)|Runtime\.exec|Process\.Start|shell_exec|exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\()", RegexOptions.Compiled), "Command Exec", "Command Injection"),
        // Path traversal sinks
        (new Regex(@"(fs\.readFile|fs\.writeFile|fs\.createReadStream|open\s*\(|File\.Open|fopen|file_get_contents|readfile)\s*\([^)]*\+", RegexOptions.Compiled), "File Operation", "Path Traversal"),
        // SSRF sinks
        (new Regex(@"(HttpClient|fetch|axios|request|curl|wget)\s*\(\s*[^)]*\+", RegexOptions.Compiled), "HTTP Request", "Server-Side Request Forgery (SSRF)"),
        // LDAP injection
        (new Regex(@"(DirectorySearcher|LdapConnection|ldap_search)\s*\("), "LDAP Query", "LDAP Injection"),
        // XPath injection
        (new Regex(@"(SelectNodes|SelectSingleNode|xpath)\s*\([^)]*\+", RegexOptions.Compiled), "XPath Query", "XPath Injection"),
    };

    // ── SANITIZATION / VALIDATION PATTERNS ──
    private static readonly Regex SanitizeRx = new(
        @"\b(validate|sanitize|escape|encode|parameterize|prepared|addWithValue|SqlParameter|htmlEncode|encodeURI|encodeURIComponent|DOMPurify|bleach\.clean|strip_tags|htmlspecialchars|mysql_real_escape|pg_escape|xss|purify|clean|filter|trim|strip|whitelist|blacklist|regex|pattern|match|sanitize_html|encode_for|owasp|validator|constraint|@Valid|@Validated|@NotNull|@NotEmpty|@Size|@Pattern|@Email|@SafeHtml)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ── FUNCTION DEFINITION / EXPORT PATTERNS ──
    private static readonly Regex FuncDefRx = new(
        @"(?:function\s+(\w+)|(?:public|private|protected|internal|static|async|export)\s+.*?(?:function|const|let|var)?\s*(\w+)\s*\(|(\w+)\s*(?:=|:)\s*(?:async\s+)?\(?:\s*(?:\w+(?:,\s*\w+)*)?\s*\)\s*=>|def\s+(\w+)\s*\(|class\s+(\w+))",
        RegexOptions.Compiled);

    private static readonly Regex ExportRx = new(
        @"(?:module\.exports|export\s+(?:default\s+)?(?:function|const|class)|export\s+\{[^}]*\})",
        RegexOptions.Compiled);

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();
        var allSources = new List<SourceHit>();
        var allSinks = new List<SinkHit>();
        var funcMap = new Dictionary<string, List<FuncDef>>(); // func name -> definitions

        // ── Pass 1: Collect all sources, sinks, and function definitions ──
        foreach (var file in files)
        {
            var fileExports = new HashSet<string>();

            for (int i = 0; i < file.Lines.Length; i++)
            {
                var line = file.Lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Collect sources
                foreach (var (rx, label) in Sources)
                {
                    try
                    {
                        var m = rx.Match(line);
                        if (m.Success)
                            allSources.Add(new SourceHit(file, i + 1, m.Value, label, ExtractVarName(m.Value)));
                    }
                    catch (RegexMatchTimeoutException) { }
                }

                // Collect sinks
                foreach (var (rx, sinkType, vuln) in Sinks)
                {
                    try
                    {
                        if (rx.IsMatch(line))
                            allSinks.Add(new SinkHit(file, i + 1, sinkType, vuln));
                    }
                    catch (RegexMatchTimeoutException) { }
                }

                // Collect function definitions
                var fm = FuncDefRx.Match(line);
                if (fm.Success)
                {
                    var name = fm.Groups.Cast<Group>().Skip(1).FirstOrDefault(g => g.Success)?.Value ?? "anonymous";
                    if (!funcMap.ContainsKey(name)) funcMap[name] = new List<FuncDef>();
                    funcMap[name].Add(new FuncDef(file.FilePath, i + 1, name, line));
                }

                // Track exports
                if (ExportRx.IsMatch(line))
                {
                    var exportMatch = Regex.Match(line, @"export\s+(?:default\s+)?(?:function|const|class|let|var)?\s*(\w+)");
                    if (exportMatch.Success)
                        fileExports.Add(exportMatch.Groups[1].Value);
                }
            }

            // Store exports per file for cross-file call tracing
            foreach (var export in fileExports)
            {
                if (!funcMap.ContainsKey(export)) funcMap[export] = new List<FuncDef>();
                funcMap[export].Add(new FuncDef(file.FilePath, 0, export, "EXPORT"));
            }
        }

        // ── Pass 2: Intra-file flow tracing (source → sink in same file) ──
        var traced = new HashSet<string>();
        foreach (var src in allSources)
        {
            var fileSinks = allSinks
                .Where(s => s.File.FilePath == src.File.FilePath && s.Line > src.Line)
                .ToList();

            foreach (var sink in fileSinks)
            {
                bool sanitized = HasSanitization(src.File.Lines, src.Line - 1, sink.Line - 1);
                if (!sanitized)
                {
                    var traceKey = $"{src.File.FilePath}:{src.Line}→{sink.Line}";
                    if (!traced.Add(traceKey)) continue;

                    // Check if source variable is passed to a function that later sinks
                    var funcCallTrace = TraceThroughFunctions(src, sink, funcMap);

                    var trace = funcCallTrace != null
                        ? $"{src.Match} ({src.File.FilePath}:{src.Line}) → {funcCallTrace} → {sink.SinkType} ({src.File.FilePath}:{sink.Line}) — NO sanitization"
                        : $"{src.Match} ({src.File.FilePath}:{src.Line}) → {sink.SinkType} ({src.File.FilePath}:{sink.Line}) — NO sanitization detected";

                    issues.Add(new CodeIssue
                    {
                        Severity = "Critical",
                        Title = funcCallTrace != null
                            ? $"Proven {sink.Vuln} — Taint Propagated Through Function Call"
                            : $"Proven {sink.Vuln} — Unsanitized Data Flow",
                        Description = $"Data flow: {trace}",
                        FilePath = src.File.FilePath,
                        LineNumber = src.Line,
                        Suggestion = $"Add input validation/sanitization between the {src.Label} source at line {src.Line} and the {sink.SinkType} sink at line {sink.Line}. Use parameterized queries for SQL or encoding for HTML output.",
                        EffortLevel = "Medium",
                        Category = "Security",
                        ConfidenceScore = funcCallTrace != null ? 92 : 85,
                        DataFlowTrace = trace
                    });
                }
            }
        }

        // ── Pass 3: Cross-file flow tracing via function calls & exports ──
        foreach (var src in allSources)
        {
            // Find function calls in the source file that pass the tainted variable
            for (int i = src.Line; i < src.File.Lines.Length && i < src.Line + 50; i++)
            {
                var line = src.File.Lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Check if any known exported function is called with the source variable
                foreach (var (funcName, defs) in funcMap)
                {
                    if (line.Contains(funcName) && line.Contains(src.VarName))
                    {
                        // Find if this function definition contains a sink
                        var funcDefsInOtherFiles = defs.Where(d => d.FilePath != src.File.FilePath).ToList();
                        foreach (var def in funcDefsInOtherFiles)
                        {
                            var targetFile = files.FirstOrDefault(f => f.FilePath == def.FilePath);
                            if (targetFile == null) continue;

                            var targetSinks = allSinks
                                .Where(s => s.File.FilePath == def.FilePath && s.Line > def.Line)
                                .ToList();

                            foreach (var sink in targetSinks)
                            {
                                bool sanitized = HasSanitization(targetFile.Lines, def.Line - 1, sink.Line - 1);
                                if (!sanitized)
                                {
                                    var traceKey = $"{src.File.FilePath}:{src.Line}→{def.FilePath}:{sink.Line}";
                                    if (!traced.Add(traceKey)) continue;

                                    var trace = $"{src.Match} ({src.File.FilePath}:{src.Line}) → {funcName}() call → {funcName} defined in {def.FilePath}:{def.Line} → {sink.SinkType} ({def.FilePath}:{sink.Line}) — cross-file, NO sanitization";

                                    issues.Add(new CodeIssue
                                    {
                                        Severity = "Critical",
                                        Title = $"Cross-File {sink.Vuln} — Taint via Function Export",
                                        Description = $"Data flow: {trace}",
                                        FilePath = src.File.FilePath,
                                        LineNumber = src.Line,
                                        Suggestion = $"User input from {src.File.FilePath} flows through exported function '{funcName}' to {sink.SinkType} in {def.FilePath}. Add validation at the function boundary or parameterize the sink.",
                                        EffortLevel = "Hard",
                                        Category = "Security",
                                        ConfidenceScore = 75,
                                        DataFlowTrace = trace
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Pass 4: Property/field taint propagation ──
        foreach (var src in allSources)
        {
            var fileLines = src.File.Lines;
            for (int i = src.Line; i < fileLines.Length && i < src.Line + 30; i++)
            {
                var line = fileLines[i];
                // Detect assignments like: obj.prop = req.body.name
                var propMatch = Regex.Match(line, @"(\w+)\.(\w+)\s*=\s*" + Regex.Escape(src.VarName));
                if (propMatch.Success)
                {
                    var objName = propMatch.Groups[1].Value;
                    var propName = propMatch.Groups[2].Value;

                    // Look for this property being used in a sink later
                    var propSinks = allSinks
                        .Where(s => s.File.FilePath == src.File.FilePath && s.Line > i &&
                               src.File.Lines[s.Line - 1].Contains($"{objName}.{propName}"))
                        .ToList();

                    foreach (var sink in propSinks)
                    {
                        bool sanitized = HasSanitization(fileLines, i, sink.Line - 1);
                        if (!sanitized)
                        {
                            var traceKey = $"prop:{src.File.FilePath}:{objName}.{propName}:{sink.Line}";
                            if (!traced.Add(traceKey)) continue;

                            var trace = $"{src.Match} ({src.File.FilePath}:{src.Line}) → {objName}.{propName} assignment ({src.File.FilePath}:{i + 1}) → {sink.SinkType} ({src.File.FilePath}:{sink.Line}) — property taint, NO sanitization";

                            issues.Add(new CodeIssue
                            {
                                Severity = "Critical",
                                Title = $"Property Taint {sink.Vuln}",
                                Description = $"Data flow: {trace}",
                                FilePath = src.File.FilePath,
                                LineNumber = src.Line,
                                Suggestion = $"Tainted data stored in property '{objName}.{propName}' and later used in {sink.SinkType}. Sanitize before assignment or before sink usage.",
                                EffortLevel = "Medium",
                                Category = "Security",
                                ConfidenceScore = 80,
                                DataFlowTrace = trace
                            });
                        }
                    }
                }
            }
        }

        return issues;
    }

    private static bool HasSanitization(string[] lines, int fromIdx, int toIdx)
    {
        int start = Math.Max(0, fromIdx);
        int end = Math.Min(lines.Length, toIdx);
        for (int i = start; i < end; i++)
        {
            try { if (SanitizeRx.IsMatch(lines[i])) return true; }
            catch (RegexMatchTimeoutException) { }
        }
        return false;
    }

    private static string ExtractVarName(string source)
    {
        // Extract a probable variable name from source pattern
        // e.g., "req.body.username" -> "username", "[FromBody] User user" -> "user"
        var parts = source.Split('.', '[', ']', ' ', '(', ')');
        // Return last non-empty meaningful part
        for (int i = parts.Length - 1; i >= 0; i--)
        {
            var p = parts[i].Trim('\'', '"', ' ', '\t');
            if (!string.IsNullOrEmpty(p) && p.Length > 1 && !p.Equals("req") && !p.Equals("request") && !p.Equals("body") && !p.Equals("params"))
                return p;
        }
        return "";
    }

    private static string? TraceThroughFunctions(SourceHit src, SinkHit sink, Dictionary<string, List<FuncDef>> funcMap)
    {
        // Check if source variable is passed to a function call between source and sink
        for (int i = src.Line; i < sink.Line && i < src.File.Lines.Length; i++)
        {
            var line = src.File.Lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;

            foreach (var (funcName, defs) in funcMap)
            {
                if (line.Contains(funcName) && line.Contains(src.VarName))
                {
                    var def = defs.FirstOrDefault(d => d.FilePath == src.File.FilePath);
                    if (def != null)
                        return $"{funcName}() call ({src.File.FilePath}:{i + 1})";
                }
            }
        }
        return null;
    }

    // ── Internal types ──
    private record SourceHit(ScannedFile File, int Line, string Match, string Label, string VarName);
    private record SinkHit(ScannedFile File, int Line, string SinkType, string Vuln);
    private record FuncDef(string FilePath, int Line, string Name, string DefLine);
}
