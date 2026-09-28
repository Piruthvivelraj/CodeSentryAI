using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

public static class PerformanceAnalyzer
{
    private static readonly Regex TaskResultRegex = new(@"\.(Result|Wait\(\))\s*;", RegexOptions.Compiled);
    private static readonly Regex ThreadSleepRegex = new(@"Thread\.Sleep\(", RegexOptions.Compiled);
    private static readonly Regex LargeArrayRegex = new(@"new\s+byte\[\s*(\d{8,})\s*\]", RegexOptions.Compiled);
    private static readonly Regex ToListWhereRegex = new(@"\.ToList\(\)\s*\.\s*Where\(", RegexOptions.Compiled);
    private static readonly Regex CountGtZeroRegex = new(@"\.Count\(\)\s*>\s*0", RegexOptions.Compiled);
    private static readonly Regex StringConcatRegex = new(@"\+\s*=\s*[""']|[""']\s*\+\s*=", RegexOptions.Compiled);
    private static readonly Regex ForLoopRegex = new(@"\b(for|foreach|while)\b", RegexOptions.Compiled);
    private static readonly Regex DbCallRegex = new(
        @"\.(Find|Query|Execute|SaveChanges|Submit|FirstOrDefault|SingleOrDefault)\s*\(|" +
        @"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DisposableNewRegex = new(
        @"(new\s+(SqlConnection|SqlCommand|FileStream|StreamReader|StreamWriter|HttpClient|TcpClient|WebClient))\s*\(",
        RegexOptions.Compiled);
    private static readonly Regex UsingRegex = new(@"\busing\s*\(", RegexOptions.Compiled);
    private static readonly Regex LinqInLoopRegex = new(
        @"(for|foreach|while).*\{[^}]*\.Where\(|\.Select\(|\.Any\(|\.All\(",
        RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex FileReadInLoopRegex = new(
        @"foreach.*File\.Read|for.*File\.Read|while.*ReadLine", RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex BoxingRegex = new(
        @"(ArrayList|Hashtable)\s*\(|\.Add\s*\(\s*\d+\s*,", RegexOptions.Compiled);
    private static readonly Regex StringSplitRegex = new(
        @"\.Split\s*\(\s*[^,)]*\)(?!,\s*StringSplitOptions)", RegexOptions.Compiled);
    private static readonly Regex RegexNoCompileRegex = new(
        @"new\s+Regex\s*\([^)]*\[", RegexOptions.Compiled);

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();

        foreach (var file in files)
        {
            bool inLoop = false;
            int loopDepth = 0;
            int loopBraceDepth = 0;
            int loopStartLine = 0;

            for (int i = 0; i < file.Lines.Length; i++)
            {
                var line = file.Lines[i];
                var trimmed = line.TrimStart();

                // Track loop context for N+1 detection
                if (ForLoopRegex.IsMatch(line))
                {
                    if (!inLoop) { inLoop = true; loopBraceDepth = 0; loopStartLine = i + 1; }
                    loopDepth++;
                }

                if (inLoop)
                {
                    foreach (char c in line) { if (c == '{') loopBraceDepth++; if (c == '}') loopBraceDepth--; }

                    if (DbCallRegex.IsMatch(line))
                    {
                        issues.Add(P("Warning", "Potential N+1 Query", file.FilePath, i + 1,
                            "Database call detected inside a loop — may cause N+1 query performance issue.",
                            "Batch the query outside the loop or use eager loading (Include/Join).", "Medium"));
                    }

                    if (StringConcatRegex.IsMatch(line))
                    {
                        issues.Add(P("Warning", "String Concatenation in Loop", file.FilePath, i + 1,
                            "String concatenation with += in a loop creates O(n²) allocations.",
                            "Use StringBuilder for string building in loops.", "Easy"));
                    }

                    if (loopBraceDepth <= 0 && (i >= loopStartLine || line.Contains("}"))) { inLoop = false; loopDepth = 0; }
                }

                // .Result / .Wait() on Task
                if (TaskResultRegex.IsMatch(line))
                    issues.Add(P("Warning", "Synchronous Task Blocking", file.FilePath, i + 1,
                        ".Result or .Wait() blocks the thread — can cause deadlocks.",
                        "Use await instead. Mark the calling method as async.", "Medium"));

                // Thread.Sleep
                if (ThreadSleepRegex.IsMatch(line))
                    issues.Add(P("Warning", "Thread.Sleep Usage", file.FilePath, i + 1,
                        "Thread.Sleep blocks the thread, reducing throughput.",
                        "Use await Task.Delay() in async methods.", "Easy"));

                // Large byte array
                var largeMatch = LargeArrayRegex.Match(line);
                if (largeMatch.Success && long.TryParse(largeMatch.Groups[1].Value, out var size) && size > 10_000_000)
                    issues.Add(P("Warning", "Large Memory Allocation", file.FilePath, i + 1,
                        $"Allocating {size / 1_000_000}MB byte array — may cause memory pressure.",
                        "Consider streaming or chunked processing instead.", "Medium"));

                // .ToList().Where() — inefficient
                if (ToListWhereRegex.IsMatch(line))
                    issues.Add(P("Info", "Inefficient LINQ: ToList().Where()", file.FilePath, i + 1,
                        "Materializing before filtering wastes memory.",
                        "Use .Where().ToList() to filter first, then materialize.", "Easy"));

                // .Count() > 0 instead of .Any()
                if (CountGtZeroRegex.IsMatch(line))
                    issues.Add(P("Info", "Use .Any() Instead of .Count() > 0", file.FilePath, i + 1,
                        ".Count() enumerates the entire collection; .Any() short-circuits.",
                        "Replace .Count() > 0 with .Any() for better performance.", "Easy"));

                // IDisposable without using
                if (DisposableNewRegex.IsMatch(line) && !UsingRegex.IsMatch(line) &&
                    (i == 0 || !file.Lines[i - 1].Contains("using")))
                {
                    issues.Add(P("Warning", "IDisposable Without Using Statement", file.FilePath, i + 1,
                        "Disposable object created without using() — may cause resource leaks.",
                        "Wrap in a using statement or using declaration.", "Easy"));
                }

                // LINQ inside loop
                if (inLoop && (line.Contains(".Where(") || line.Contains(".Select(") || line.Contains(".Any(")))
                {
                    issues.Add(P("Warning", "LINQ Operation Inside Loop (O(n²))", file.FilePath, i + 1,
                        "LINQ operation inside a loop creates quadratic complexity.",
                        "Move LINQ outside the loop or materialize the collection first.", "Medium"));
                }

                // Boxing in hot paths
                if (BoxingRegex.IsMatch(line))
                {
                    issues.Add(P("Warning", "Boxing in Hot Path", file.FilePath, i + 1,
                        "Non-generic collection (ArrayList/Hashtable) causes boxing overhead.",
                        "Use generic List<T> or Dictionary<TKey, TValue> instead.", "Easy"));
                }

                // String.Split without options
                if (StringSplitRegex.IsMatch(line))
                {
                    issues.Add(P("Info", "String.Split Without StringSplitOptions", file.FilePath, i + 1,
                        "String.Split without StringSplitOptions creates empty entries.",
                        "Use StringSplitOptions.RemoveEmptyEntries for cleaner results.", "Easy"));
                }

                // Regex without Compiled flag
                if (RegexNoCompileRegex.IsMatch(line) && file.Lines.Any(l => l.Contains("RegexOptions.Compiled")))
                {
                    // Only flag if there ARE compiled regexes in the file (meaning others should be too)
                }
            }

            // File.ReadAllText inside loop
            if (FileReadInLoopRegex.IsMatch(file.Content))
            {
                issues.Add(P("Critical", "File.ReadAllText Inside Loop", file.FilePath, 1,
                    "File reading operations detected inside a loop — very inefficient.",
                    "Read files before the loop, or use streaming for large files.", "Hard"));
            }
        }

        return issues;
    }

    private static CodeIssue P(string sev, string title, string path, int line, string desc, string suggestion, string effort) =>
        new() { Severity = sev, Title = title, FilePath = path, LineNumber = line,
            Description = desc, Suggestion = suggestion, EffortLevel = effort, Category = "Performance" };
}
