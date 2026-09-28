using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

public static class QualityAnalyzer
{
    private static readonly Regex MethodRegex = new(
        @"^\s*(public|private|protected|internal|static|async|override|virtual|abstract|sealed|\s)+" +
        @"\s+\w[\w<>\[\],\s\?]*\s+(\w+)\s*\(", RegexOptions.Compiled);

    private static readonly Regex ComplexityRegex = new(
        @"\b(if|else\s+if|for|foreach|while|do|switch|case|catch)\b|&&|\|\||\?[^?].*:", RegexOptions.Compiled);

    private static readonly Regex EmptyCatchRegex = new(
        @"catch\s*(\([^)]*\))?\s*\{\s*\}", RegexOptions.Compiled);

    private static readonly Regex BooleanParamRegex = new(
        @"(public|private|protected|internal)\s+\w+[\w<>\[\],\s]*\s+\w+\s*\(\s*bool\s+\w+", RegexOptions.Compiled);

    private static readonly Regex DateTimeNowRegex = new(
        @"\bDateTime\.Now\b(?!.*Utc)", RegexOptions.Compiled);

    private static readonly Regex TaskBlockingRegex = new(
        @"\.(Result|Wait\(\))\s*;", RegexOptions.Compiled);

    private static readonly Regex ThreadSleepAsyncRegex = new(
        @"Thread\.Sleep\(", RegexOptions.Compiled);

    private static readonly Regex StringComparisonRegex = new(
        @"\.Equals\s*\(\s*[\""]|String\.Compare\s*\(", RegexOptions.Compiled);

    private static readonly Regex TooManyParamsRegex = new(
        @"(public|private|protected|internal)\s+\w+[\w<>\[\],\s]*\s+\w+\s*\([^)]{200,}\)", RegexOptions.Compiled);

    private static readonly Regex ImplicitCastRegex = new(
        @"\((?:int|float|double|long)\s*\)\s*\w+\s*[=;]", RegexOptions.Compiled);

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();
        var fileNames = files.Select(f => f.FilePath.ToLowerInvariant()).ToList();

        foreach (var file in files)
        {
            // God Class / Long File
            if (file.LineCount > 1000)
                issues.Add(Issue("Critical", "Massive File Detected", file.FilePath, 1,
                    $"File has {file.LineCount} lines — immediate refactoring required.",
                    "Split into smaller classes following Single Responsibility Principle.", "Hard"));
            else if (file.LineCount > 500)
                issues.Add(Issue("Warning", "Large File Detected", file.FilePath, 1,
                    $"File has {file.LineCount} lines, violates Single Responsibility.",
                    "Consider extracting cohesive functionality into separate files.", "Medium"));

            AnalyzeMethods(file, issues);
            AnalyzeNesting(file, issues);
            AnalyzeEmptyCatch(file, issues);
            AnalyzeCodeSmells(file, issues);
            AnalyzeStaticMutableState(file, issues);
            AnalyzeBoolParams(file, issues);
            AnalyzeDateTimeUsage(file, issues);
            AnalyzeTaskBlocking(file, issues);
            AnalyzeTooManyParams(file, issues);
        }

        AnalyzeDuplicates(files, issues);
        AnalyzeCircularDeps(files, issues, fileNames);
        return issues;
    }

    private static void AnalyzeMethods(ScannedFile file, List<CodeIssue> issues)
    {
        int methodStart = -1;
        string methodName = "";
        int braceDepth = 0;
        int complexity = 1;
        bool inMethod = false;
        int paramCount = 0;

        for (int i = 0; i < file.Lines.Length; i++)
        {
            var line = file.Lines[i];
            var match = MethodRegex.Match(line);

            if (match.Success && !inMethod)
            {
                methodStart = i;
                methodName = match.Groups[2].Value;
                braceDepth = 0;
                complexity = 1;
                inMethod = true;
                paramCount = line.Count(c => c == ',') + 1;
            }

            if (inMethod)
            {
                foreach (char c in line)
                {
                    if (c == '{') braceDepth++;
                    if (c == '}') braceDepth--;
                }

                var cMatches = ComplexityRegex.Matches(line);
                complexity += cMatches.Count;

                if (braceDepth <= 0 && i > methodStart)
                {
                    int methodLength = i - methodStart;

                    if (methodLength > 100)
                        issues.Add(Issue("Critical", "God Method Detected", file.FilePath, methodStart + 1,
                            $"Method '{methodName}' is {methodLength} lines long.",
                            "Extract logic into smaller methods. Aim for <30 lines per method.", "Hard"));
                    else if (methodLength > 50)
                        issues.Add(Issue("Warning", "Long Method Detected", file.FilePath, methodStart + 1,
                            $"Method '{methodName}' is {methodLength} lines.",
                            "Consider refactoring into smaller focused methods.", "Medium"));

                    if (complexity > 20)
                        issues.Add(Issue("Critical", "Extreme Cyclomatic Complexity", file.FilePath, methodStart + 1,
                            $"Method '{methodName}' has cyclomatic complexity of {complexity}.",
                            "Reduce branching — extract conditions into methods, use strategy pattern.", "Hard"));
                    else if (complexity > 10)
                        issues.Add(Issue("Warning", "High Cyclomatic Complexity", file.FilePath, methodStart + 1,
                            $"Method '{methodName}' has a complexity of {complexity}.",
                            "Simplify logic — extract helper methods, reduce nesting.", "Medium"));

                    inMethod = false;
                }
            }
        }
    }

    private static void AnalyzeNesting(ScannedFile file, List<CodeIssue> issues)
    {
        int maxDepth = 0;
        int depth = 0;
        int maxLine = 0;

        for (int i = 0; i < file.Lines.Length; i++)
        {
            foreach (char c in file.Lines[i])
            {
                if (c == '{') { depth++; if (depth > maxDepth) { maxDepth = depth; maxLine = i + 1; } }
                if (c == '}') depth--;
            }
        }

        if (maxDepth >= 5)
            issues.Add(Issue("Warning", "Deep Nesting Detected", file.FilePath, maxLine,
                $"Nesting depth of {maxDepth} levels reduces readability.",
                "Use early returns, guard clauses, or extract nested logic into methods.", "Medium"));
    }

    private static void AnalyzeEmptyCatch(ScannedFile file, List<CodeIssue> issues)
    {
        var content = file.Content;
        foreach (Match m in EmptyCatchRegex.Matches(content))
        {
            var lineNum = content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Warning", "Empty Exception Handler", file.FilePath, lineNum,
                "Empty catch block silently swallows exceptions.",
                "Log the exception or handle it appropriately. Never silently catch.", "Easy"));
        }
    }

    private static void AnalyzeCodeSmells(ScannedFile file, List<CodeIssue> issues)
    {
        bool isTestFile = file.FilePath.Contains("test", StringComparison.OrdinalIgnoreCase) ||
                          file.FilePath.Contains("spec", StringComparison.OrdinalIgnoreCase);

        for (int i = 0; i < file.Lines.Length; i++)
        {
            var line = file.Lines[i].TrimStart();

            if (!isTestFile)
            {
                if (line.StartsWith("Console.WriteLine("))
                    issues.Add(Issue("Info", "Console.WriteLine in Production", file.FilePath, i + 1,
                        "Console output should not be in production code.", "Use ILogger or structured logging.", "Easy"));
                if (line.StartsWith("System.out.println("))
                    issues.Add(Issue("Info", "System.out.println in Production", file.FilePath, i + 1,
                        "Console output left in production code.", "Use SLF4J or Log4j for structured logging.", "Easy"));
            }

            // Commented out code: 3+ consecutive comment lines
            if (i + 2 < file.Lines.Length)
            {
                var l1 = file.Lines[i].TrimStart();
                var l2 = file.Lines[i + 1].TrimStart();
                var l3 = file.Lines[i + 2].TrimStart();
                if ((l1.StartsWith("//") && l2.StartsWith("//") && l3.StartsWith("//")) ||
                    (l1.StartsWith("#") && l2.StartsWith("#") && l3.StartsWith("#") && file.Language == "Python"))
                {
                    if (i == 0 || !file.Lines[i - 1].TrimStart().StartsWith("//"))
                        issues.Add(Issue("Info", "Commented Out Code Block", file.FilePath, i + 1,
                            "Block of commented-out code detected.", "Remove dead code — use version control for history.", "Easy"));
                }
            }
        }
    }

    private static void AnalyzeStaticMutableState(ScannedFile file, List<CodeIssue> issues)
    {
        var staticMutable = new Regex(@"(private|protected|internal)\s+(?:(?:static|readonly)\s+)?(?!const\s)(List|Dictionary|Hashtable|Array|Queue|Stack|Set)\b", RegexOptions.Compiled);
        var matches = staticMutable.Matches(file.Content);
        foreach (Match m in matches)
        {
            var lineNum = file.Content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Critical", "Static Mutable State Detected", file.FilePath, lineNum,
                "Static non-readonly mutable collection detected — not thread-safe.",
                "Use thread-safe collections, locks, or move to instance state.", "Medium"));
        }
    }

    private static void AnalyzeBoolParams(ScannedFile file, List<CodeIssue> issues)
    {
        foreach (Match m in BooleanParamRegex.Matches(file.Content))
        {
            var lineNum = file.Content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Warning", "Boolean Parameter Trap", file.FilePath, lineNum,
                "Method uses boolean parameter — reduces readability.",
                "Replace bool with named parameters or enum for clarity.", "Easy"));
        }
    }

    private static void AnalyzeDateTimeUsage(ScannedFile file, List<CodeIssue> issues)
    {
        foreach (Match m in DateTimeNowRegex.Matches(file.Content))
        {
            var lineNum = file.Content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Warning", "DateTime.Now Instead of DateTime.UtcNow", file.FilePath, lineNum,
                "DateTime.Now used — returns local time which causes bugs across time zones.",
                "Use DateTime.UtcNow for timestamps, or DateTimeOffset for timezone-aware times.", "Easy"));
        }
    }

    private static void AnalyzeTaskBlocking(ScannedFile file, List<CodeIssue> issues)
    {
        foreach (Match m in TaskBlockingRegex.Matches(file.Content))
        {
            var lineNum = file.Content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Warning", "Synchronous Task Blocking (.Result/.Wait())", file.FilePath, lineNum,
                ".Result or .Wait() blocks the thread — can cause deadlocks.",
                "Use await instead. Mark the calling method as async.", "Medium"));
        }

        foreach (Match m in ThreadSleepAsyncRegex.Matches(file.Content))
        {
            var lineNum = file.Content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Warning", "Thread.Sleep in Async Code", file.FilePath, lineNum,
                "Thread.Sleep blocks the thread, reducing throughput.",
                "Use await Task.Delay() in async methods.", "Easy"));
        }
    }

    private static void AnalyzeTooManyParams(ScannedFile file, List<CodeIssue> issues)
    {
        foreach (Match m in TooManyParamsRegex.Matches(file.Content))
        {
            var lineNum = file.Content[..m.Index].Split('\n').Length;
            issues.Add(Issue("Info", "Method Has Too Many Parameters", file.FilePath, lineNum,
                "Method has more than 5 parameters — reduces readability.",
                "Group parameters into a parameter object or DTO.", "Easy"));
        }
    }

    private static void AnalyzeDuplicates(List<ScannedFile> files, List<CodeIssue> issues)
    {
        const int blockSize = 8;
        var blocks = new Dictionary<string, List<(string File, int Line)>>();

        foreach (var file in files)
        {
            if (file.LineCount < blockSize) continue;

            for (int i = 0; i <= file.Lines.Length - blockSize; i++)
            {
                var normalized = string.Join("\n", file.Lines.Skip(i).Take(blockSize)
                    .Select(l => l.Trim().ToLowerInvariant()))
                    .Trim();

                if (normalized.Length < 40) continue;

                var key = normalized;
                if (!blocks.ContainsKey(key)) blocks[key] = new();
                blocks[key].Add((file.FilePath, i + 1));
            }
        }

        var reported = new HashSet<string>();
        foreach (var kvp in blocks.Where(b => b.Value.Select(v => v.File).Distinct().Count() >= 2))
        {
            var locations = kvp.Value.GroupBy(v => v.File).Select(g => g.First()).Take(3).ToList();
            var key = string.Join("|", locations.Select(l => $"{l.File}:{l.Line}"));
            if (reported.Contains(key)) continue;
            reported.Add(key);

            var locStr = string.Join(", ", locations.Select(l => $"{l.File}:{l.Line}"));
            issues.Add(Issue("Warning", "Duplicate Code Block", locations[0].File, locations[0].Line,
                $"Identical {blockSize}-line block found at: {locStr}",
                "Extract duplicated logic into a shared method or utility class.", "Medium"));

            if (reported.Count >= 15) break;
        }
    }

    private static void AnalyzeCircularDeps(List<ScannedFile> files, List<CodeIssue> issues, List<string> fileNames)
    {
        // Detect circular using/import chains by looking for mutual imports
        var usingMap = new Dictionary<string, HashSet<string>>();
        foreach (var file in files)
        {
            var deps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var imports = new Regex(@"#include\s*[<""]([^\s>""]+)|using\s+([\w\.]+)\b", RegexOptions.Compiled);
            foreach (Match m in imports.Matches(file.Content))
            {
                var dep = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
                if (!string.IsNullOrEmpty(dep))
                    deps.Add(dep);
            }
            usingMap[file.FilePath] = deps;
        }

        // Issue 14 FIX: Normalize both sides to filename-only for comparison
        // so that full relative paths and bare filenames can match
        foreach (var (file, deps) in usingMap)
        {
            var fileBaseName = Path.GetFileNameWithoutExtension(file);
            foreach (var dep in deps)
            {
                var depFile = files.FirstOrDefault(f =>
                    f.FilePath.Contains(dep, StringComparison.OrdinalIgnoreCase));
                if (depFile != null && usingMap.TryGetValue(depFile.FilePath, out var transitive))
                {
                    // Normalize: check if the transitive dep references this file
                    // by comparing against both the filename and the full path
                    var fileNameOnly = Path.GetFileName(file);
                    var fileNameNoExt = Path.GetFileNameWithoutExtension(file);
                    bool isCircular = transitive.Any(t =>
                        string.Equals(t, fileNameOnly, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(t, fileNameNoExt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(t, file, StringComparison.OrdinalIgnoreCase) ||
                        file.Contains(t, StringComparison.OrdinalIgnoreCase));

                    if (isCircular)
                    {
                        issues.Add(Issue("Critical", "Circular Dependency Detected", file, 1,
                            $"Circular import chain detected between {Path.GetFileName(file)} and {Path.GetFileName(depFile.FilePath)}.",
                            "Refactor to use dependency injection or shared interfaces.", "Hard"));
                        break;
                    }
                }
            }
        }
    }

    private static CodeIssue Issue(string sev, string title, string path, int line, string desc, string suggestion, string effort) =>
        new() { Severity = sev, Title = title, FilePath = path, LineNumber = line,
            Description = desc, Suggestion = suggestion, EffortLevel = effort, Category = "Quality" };
}
