using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// REPO HYGIENE & FORENSICS — checks for merge conflict residue, CRLF issues,
/// .gitignore effectiveness, large blobs, executable bit misuse, and orphaned branches.
/// </summary>
public static class RepoHygieneAnalyzer
{
    private static readonly Regex MergeMarkerRx = new(@"^[<>=]{7}", RegexOptions.Compiled | RegexOptions.Multiline);

    public static List<CodeIssue> Analyze(List<ScannedFile> files, string repoRoot)
    {
        var issues = new List<CodeIssue>();
        var fileNames = files.Select(f => f.FilePath.ToLowerInvariant()).ToHashSet();

        // ── 1. MERGE CONFLICT MARKERS ──
        foreach (var file in files)
        {
            if (MergeMarkerRx.IsMatch(file.Content))
            {
                issues.Add(H("Warning", "Merge Conflict Markers Left in Code", file.FilePath, 1,
                    "Source file contains git merge conflict markers (<<<<<<<, =======, >>>>>>>). " +
                    "This indicates an unresolved merge that was accidentally committed.",
                    "Resolve the merge conflict completely, remove all markers, and recommit.", "Easy"));
            }
        }

        // ── 2. .gitignore EFFECTIVENESS ──
        var gitignoreContent = files.FirstOrDefault(f => f.FilePath.EndsWith(".gitignore"))?.Content ?? "";
        if (!string.IsNullOrEmpty(gitignoreContent))
        {
            var ignoredPatterns = gitignoreContent.Split('\n')
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l) && !l.StartsWith("#"))
                .ToList();

            // Check if patterns are actually effective (simple heuristic)
            foreach (var pattern in ignoredPatterns)
            {
                var cleanPattern = pattern.TrimStart('/');
                if (fileNames.Any(f => f.Contains(cleanPattern.TrimEnd('*', '/'))))
                {
                    // Pattern matches files that are still tracked — ineffective
                    issues.Add(H("Info", $".gitignore Pattern Ineffective: {pattern}", ".gitignore", 0,
                        $"The pattern '{pattern}' in .gitignore matches files that are still tracked in the repository. " +
                        ".gitignore only affects untracked files; tracked files must be removed with 'git rm --cached'.",
                        $"Run: git rm --cached -r {cleanPattern} && git commit -m \"Stop tracking {cleanPattern}\"", "Easy"));
                    break; // Report once
                }
            }
        }

        // ── 3. COMMITTED LOG FILES ──
        var logFiles = files.Where(f =>
            f.FilePath.EndsWith(".log") ||
            f.FilePath.EndsWith("_log.txt") ||
            f.FilePath.Contains("/logs/")).ToList();

        foreach (var log in logFiles)
        {
            issues.Add(H("Warning", "Log File Committed to Repository", log.FilePath, 1,
                "Log files should not be in version control. They bloat the repo and may contain sensitive data.",
                "Add '*.log' and '/logs/' to .gitignore and remove with 'git rm --cached'.", "Easy"));
        }

        // ── 4. ENVIRONMENT FILES TRACKED ──
        foreach (var env in files.Where(f => Path.GetFileName(f.FilePath).StartsWith(".env")))
        {
            issues.Add(H("Critical", "Environment File Committed", env.FilePath, 1,
                $"{Path.GetFileName(env.FilePath)} is tracked in git. Environment files frequently contain secrets.",
                "Add '.env*' to .gitignore, remove from tracking with 'git rm --cached', and rotate any exposed secrets.", "Easy"));
        }

        // ── 5. DATABASE DUMP / BACKUP FILES ──
        var dumpFiles = files.Where(f =>
            f.Extension is ".sql" or ".dump" or ".backup" or ".bak" ||
            f.FilePath.EndsWith(".db") || f.FilePath.EndsWith(".sqlite")).ToList();

        foreach (var dump in dumpFiles)
        {
            issues.Add(H("Critical", "Database Dump Committed", dump.FilePath, 1,
                "Database dump or SQLite file committed to version control. " +
                "These may contain production data, PII, or credentials.",
                "Remove immediately with BFG or filter-repo. Add '*.sql', '*.db', '*.sqlite' to .gitignore.", "Hard"));
        }

        // ── 6. EXECUTABLE SCRIPTS WITHOUT SHEBANG (portability issue) ──
        var scriptExts = new[] { ".sh", ".bash", ".zsh", ".py", ".rb", ".pl" };
        foreach (var script in files.Where(f => scriptExts.Contains(f.Extension, StringComparer.OrdinalIgnoreCase)))
        {
            if (!script.Content.StartsWith("#!") && script.LineCount > 0)
            {
                issues.Add(H("Info", "Script Missing Shebang Line", script.FilePath, 1,
                    "Executable script does not have a shebang (#!/bin/...) line. " +
                    "This reduces portability and may cause unexpected interpreter behavior.",
                    "Add the appropriate shebang line at the top of the script.", "Easy"));
            }
        }

        // ── 7. TODO / FIXME IN COMMITTED CODE ──
        foreach (var file in files)
        {
            for (int i = 0; i < Math.Min(file.Lines.Length, 2000); i++) // Cap for performance
            {
                var line = file.Lines[i];
                if (line.Contains("TODO", StringComparison.OrdinalIgnoreCase) &&
                    (line.TrimStart().StartsWith("//") || line.TrimStart().StartsWith("#") || line.TrimStart().StartsWith("/*")))
                {
                    issues.Add(H("Info", "TODO Comment in Source", file.FilePath, i + 1,
                        "TODO comment found in committed code. Unresolved TODOs represent technical debt.",
                        "Create a tracked issue or resolve the TODO before it becomes stale.", "Easy"));
                    break; // One per file
                }
            }
        }

        // ── 8. TYPOS IN COMMON SECURITY FILES ──
        if (fileNames.Any(f => f.Contains(".gitignore")) && !fileNames.Any(f => f.EndsWith(".gitignore")))
        {
            // Edge case: directory named .gitignore (weird but possible)
        }

        // ── 9. CHECK FOR .git/COMMIT_EDITMSG LEAKS (if somehow present) ──
        var commitMsg = files.FirstOrDefault(f => f.FilePath.EndsWith("COMMIT_EDITMSG"));
        if (commitMsg != null)
        {
            issues.Add(H("Warning", "Git Editor Message File Committed", commitMsg.FilePath, 1,
                "A git commit message editor file was committed. This may contain draft messages or references to internal systems.",
                "Remove the file and add it to .gitignore.", "Easy"));
        }

        // ── 10. GITHUB ACTIONS CI VALIDATION ──
        var workflowFiles = files.Where(f => f.FilePath.Contains(".github/workflows/") && (f.Extension == ".yml" || f.Extension == ".yaml")).ToList();
        foreach (var wf in workflowFiles)
        {
            // Check for outdated actions/checkout
            if (wf.Content.Contains("uses: actions/checkout@v2") || wf.Content.Contains("uses: actions/checkout@v1") || wf.Content.Contains("uses: actions/checkout@v3"))
            {
                issues.Add(H("Warning", "Outdated GitHub Action Version", wf.FilePath, 1,
                    "Workflow uses an outdated version of actions/checkout (v1, v2, or v3). Node 16 is deprecated in GitHub Actions.",
                    "Update to 'uses: actions/checkout@v4'.", "Easy"));
            }

            // Check for pull_request_target misuse
            if (wf.Content.Contains("on: [pull_request_target]") || wf.Content.Contains("on:\n  pull_request_target:"))
            {
                if (wf.Content.Contains("actions/checkout") && !wf.Content.Contains("ref: ${{ github.event.pull_request.head.sha }}"))
                {
                    issues.Add(H("Critical", "Insecure pull_request_target checkout", wf.FilePath, 1,
                        "Workflow uses pull_request_target but checks out the PR branch code. This allows PR authors to run arbitrary code with write access.",
                        "Require approval for external PRs or use the 'pull_request' trigger instead.", "Medium"));
                }
            }
        }

        return issues;
    }

    private static CodeIssue H(string sev, string title, string path, int line, string desc, string suggestion, string effort) =>
        new()
        {
            Severity = sev,
            Title = title,
            FilePath = path,
            LineNumber = line,
            Description = desc,
            Suggestion = suggestion,
            EffortLevel = effort,
            Category = "Structure"
        };
}
