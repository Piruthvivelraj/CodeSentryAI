using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// Feature 4 — Post-processing step that calculates a ConfidenceScore (0–100) for every CodeIssue.
/// Scores are based on context-aware factors: whether the match is in actual code vs. comments,
/// whether the same issue appears across multiple files, and whether the file type matches the
/// expected vulnerability context. Issues scoring below 40 are downgraded to INFO to eliminate
/// false positives.
/// </summary>
public static class ConfidenceScorer
{
    // Comment prefixes for various languages
    private static readonly string[] CommentPrefixes =
        { "//", "#", "--", "/*", "* ", "///", "/**", "'''", "\"\"\"", "REM ", ";" };

    // Map vulnerability categories to file extensions where they are most relevant
    private static readonly Dictionary<string, HashSet<string>> VulnContextMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SQL Injection"] = new(StringComparer.OrdinalIgnoreCase)
            { ".js", ".ts", ".py", ".cs", ".java", ".php", ".rb", ".go", ".rs" },
        ["Cross-Site Scripting (XSS)"] = new(StringComparer.OrdinalIgnoreCase)
            { ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte", ".php", ".razor", ".cshtml" },
        ["Command Injection"] = new(StringComparer.OrdinalIgnoreCase)
            { ".js", ".ts", ".py", ".cs", ".java", ".php", ".rb", ".go", ".sh", ".bash" },
        ["Hardcoded Password"] = new(StringComparer.OrdinalIgnoreCase)
            { ".js", ".ts", ".py", ".cs", ".java", ".env", ".json", ".yml", ".yaml", ".config", ".xml", ".php", ".go", ".rb" },
        ["Hardcoded Secret Key"] = new(StringComparer.OrdinalIgnoreCase)
            { ".js", ".ts", ".py", ".cs", ".java", ".env", ".json", ".yml", ".yaml", ".config", ".xml" },
        ["Hardcoded API Key"] = new(StringComparer.OrdinalIgnoreCase)
            { ".js", ".ts", ".py", ".cs", ".java", ".env", ".json", ".yml", ".yaml", ".config", ".xml" },
    };

    // Categories that apply broadly to all code files
    private static readonly HashSet<string> BroadCategories = new(StringComparer.OrdinalIgnoreCase)
        { "Security", "Quality", "Performance", "Structure", "Dependency", "ApiSurface" };

    /// <summary>
    /// Scores all issues and downgrades low-confidence ones to INFO.
    /// Call this AFTER all analyzers have run.
    /// </summary>
    public static void Score(List<CodeIssue> issues, List<ScannedFile> files)
    {
        // Pre-compute: count of each issue title across distinct files
        var titleFileCount = issues
            .GroupBy(i => i.Title, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(i => i.FilePath).Distinct().Count(), StringComparer.OrdinalIgnoreCase);

        // Build a fast lookup from file path to ScannedFile
        var fileMap = files.ToDictionary(f => f.FilePath, f => f, StringComparer.OrdinalIgnoreCase);

        foreach (var issue in issues)
        {
            // If the analyzer already set a score (e.g., GitHistorySecretScanner sets 95), keep it
            if (issue.ConfidenceScore > 0) continue;

            int score = 0;

            // ── Factor 1: Pattern matched in actual code (not comment/string) → +40 ──
            if (IsInActualCode(issue, fileMap))
                score += 40;

            // ── Factor 2: Same pattern found in multiple files → +20 ──
            if (titleFileCount.TryGetValue(issue.Title, out int fileCount) && fileCount > 1)
                score += 20;

            // ── Factor 3: Pattern on executable line (not commented out) → +20 ──
            if (IsOnExecutableLine(issue, fileMap))
                score += 20;

            // ── Factor 4: File type matches expected vulnerability context → +20 ──
            if (FileTypeMatchesContext(issue))
                score += 20;

            issue.ConfidenceScore = Math.Clamp(score, 0, 100);

            // ── Downgrade low-confidence issues to INFO ──
            if (issue.ConfidenceScore < 40 && issue.Severity != "Info")
            {
                issue.Severity = "Info";
            }
        }
    }

    /// <summary>
    /// Checks whether the matched line is actual code (not a comment or inside a string literal
    /// that looks like documentation).
    /// </summary>
    private static bool IsInActualCode(CodeIssue issue, Dictionary<string, ScannedFile> fileMap)
    {
        if (!fileMap.TryGetValue(issue.FilePath, out var file)) return true; // default to true if file not found
        if (issue.LineNumber <= 0 || issue.LineNumber > file.Lines.Length) return true;

        var line = file.Lines[issue.LineNumber - 1].TrimStart();

        // Check if line starts with a comment prefix
        foreach (var prefix in CommentPrefixes)
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal))
                return false; // It's a comment
        }

        // Check if the match is inside a log/print/console statement (often false positive)
        if (Regex.IsMatch(line, @"\b(console\.log|print|Debug\.WriteLine|Logger\.\w+|log\.\w+|_logger\.\w+)\s*\(",
            RegexOptions.IgnoreCase))
        {
            return false; // It's a log statement referencing the keyword
        }

        return true;
    }

    /// <summary>
    /// Checks whether the line is executable (not blank, not pure comment, not in a comment block).
    /// </summary>
    private static bool IsOnExecutableLine(CodeIssue issue, Dictionary<string, ScannedFile> fileMap)
    {
        if (!fileMap.TryGetValue(issue.FilePath, out var file)) return true;
        if (issue.LineNumber <= 0 || issue.LineNumber > file.Lines.Length) return true;

        var line = file.Lines[issue.LineNumber - 1].Trim();
        if (string.IsNullOrWhiteSpace(line)) return false;

        // Check for pure comment lines
        foreach (var prefix in CommentPrefixes)
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal))
                return false;
        }

        // Check for being inside a block comment — scan up for /* without closing */
        bool inBlockComment = false;
        int checkStart = Math.Max(0, issue.LineNumber - 50);
        for (int i = checkStart; i < issue.LineNumber - 1; i++)
        {
            var checkLine = file.Lines[i];
            if (checkLine.Contains("/*")) inBlockComment = true;
            if (checkLine.Contains("*/")) inBlockComment = false;
        }

        return !inBlockComment;
    }

    /// <summary>
    /// Checks whether the file's extension matches the expected context for this type of vulnerability.
    /// </summary>
    private static bool FileTypeMatchesContext(CodeIssue issue)
    {
        var ext = System.IO.Path.GetExtension(issue.FilePath);
        if (string.IsNullOrEmpty(ext)) return true;

        // Check specific vulnerability context maps
        foreach (var (vuln, extensions) in VulnContextMap)
        {
            if (issue.Title.Contains(vuln, StringComparison.OrdinalIgnoreCase) ||
                issue.Description.Contains(vuln, StringComparison.OrdinalIgnoreCase))
            {
                return extensions.Contains(ext);
            }
        }

        // For broad categories, most code file extensions are valid context
        if (BroadCategories.Contains(issue.Category))
        {
            var codeExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".js", ".ts", ".jsx", ".tsx", ".py", ".cs", ".java", ".go", ".rs", ".rb",
                ".php", ".swift", ".kt", ".scala", ".c", ".cpp", ".h", ".hpp",
                ".html", ".css", ".json", ".xml", ".yaml", ".yml", ".env",
                ".vue", ".svelte", ".razor", ".cshtml"
            };
            return codeExtensions.Contains(ext);
        }

        return true; // Default to true for unknown categories
    }
}
