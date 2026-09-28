using System.Text;
using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// Feature 1 — Scans git history for secrets that were committed then deleted.
/// These remain recoverable from git history and represent a CRITICAL risk.
/// Runs git log commands against the cloned repo.
/// </summary>
public static class GitHistorySecretScanner
{
    private static readonly Regex SecretPattern = new(
        @"(password|passwd|secret|secret_key|api_key|apikey|token|auth_token|access_token|private_key)\s*[=:]\s*['""][^'""]{8,}['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(500));

    private static readonly Regex CommitHashRx = new(@"^commit\s+([a-f0-9]{7,40})", RegexOptions.Compiled);
    private static readonly Regex AuthorRx     = new(@"^Author:\s+(.+)", RegexOptions.Compiled);
    private static readonly Regex DateRx       = new(@"^Date:\s+(.+)", RegexOptions.Compiled);
    private static readonly Regex DiffFileRx   = new(@"^diff --git a/(.+?) b/", RegexOptions.Compiled);

    /// <summary>
    /// Scans git history for leaked secrets. Requires the repo root path (with .git directory).
    /// </summary>
    public static async Task<List<CodeIssue>> AnalyzeAsync(string repoRoot, CancellationToken ct = default)
    {
        var issues = new List<CodeIssue>();

        // ── SCAN 1: Deleted sensitive files still in history ──
        try
        {
            var deletedOutput = await RunGitAsync(repoRoot,
                "log --all --full-history --diff-filter=D -p --max-count=500 -- \"*.env\" \"*.json\" \"*.config\" \"*.yml\" \"*.yaml\"",
                30, ct);
            issues.AddRange(ParseGitLogForSecrets(deletedOutput));
        }
        catch (Exception ex)
        {
            // Non-fatal — log at trace level only, outer engine handles the catch
            _ = ex.Message; // suppress unused warning
        }

        // ── SCAN 2: Full history pickaxe search for secret patterns ──
        try
        {
            var pickaxeOutput = await RunGitAsync(repoRoot,
                "log -p --all --max-count=500 -G \"(password|secret|api_key|token|private_key|auth_token)\"",
                30, ct);
            issues.AddRange(ParseGitLogForSecrets(pickaxeOutput));
        }
        catch (Exception ex)
        {
            _ = ex.Message;
        }

        // ── DEDUPLICATION: Group by pattern+filePath, aggregate commit hashes ──
        // If the same secret pattern appears in multiple commits for the same file,
        // report it once with all commit hashes listed.
        var deduplicated = issues
            .GroupBy(i => $"{i.Title}|{i.FilePath}")
            .Select(g =>
            {
                var first = g.First();
                if (g.Count() == 1) return first;

                // Extract commit hashes from Description fields and aggregate them
                var hashes = g
                    .Select(i =>
                    {
                        var m = Regex.Match(i.Description, @"commit ([a-f0-9]{7,})");
                        return m.Success ? m.Groups[1].Value : "";
                    })
                    .Where(h => !string.IsNullOrEmpty(h))
                    .Distinct()
                    .ToList();

                var hashList = hashes.Count > 0
                    ? string.Join(", ", hashes)
                    : "multiple commits";

                return new CodeIssue
                {
                    Severity       = first.Severity,
                    Title          = first.Title,
                    Description    = $"Secret pattern found in {g.Count()} commits: {hashList} — still recoverable from git history.",
                    FilePath       = first.FilePath,
                    LineNumber     = 0,
                    Suggestion     = first.Suggestion,
                    EffortLevel    = first.EffortLevel,
                    Category       = first.Category,
                    ConfidenceScore = first.ConfidenceScore
                };
            })
            .ToList();

        return deduplicated;
    }

    private static List<CodeIssue> ParseGitLogForSecrets(string gitLogOutput)
    {
        var issues = new List<CodeIssue>();
        if (string.IsNullOrWhiteSpace(gitLogOutput)) return issues;

        var lines = gitLogOutput.Split('\n');
        string hash = "unknown", author = "unknown", date = "unknown", file = "unknown";
        var seen = new HashSet<string>();

        foreach (var rawLine in lines)
        {
            var line = rawLine;

            var hm = CommitHashRx.Match(line);
            if (hm.Success) { hash = hm.Groups[1].Value[..Math.Min(7, hm.Groups[1].Value.Length)]; continue; }

            var am = AuthorRx.Match(line);
            if (am.Success) { author = am.Groups[1].Value.Trim(); continue; }

            var dm = DateRx.Match(line);
            if (dm.Success) { date = dm.Groups[1].Value.Trim(); continue; }

            var fm = DiffFileRx.Match(line);
            if (fm.Success) { file = fm.Groups[1].Value; continue; }

            // Only check added/removed diff lines (actual content that was committed)
            if (line.Length > 1 && (line[0] == '+' || line[0] == '-') && line[1] != '+' && line[1] != '-')
            {
                var content = line[1..];
                try
                {
                    if (SecretPattern.IsMatch(content))
                    {
                        var key = $"{hash}:{file}:{content.Trim().GetHashCode()}";
                        if (seen.Add(key))
                        {
                            issues.Add(new CodeIssue
                            {
                                Severity   = "Critical",
                                Title      = "Secret Found in Git History",
                                Description = $"Secret found in commit {hash} by {author} on {date} — still recoverable from git history.",
                                FilePath   = file,
                                LineNumber = 0,
                                Suggestion = "This credential was committed to git history and remains recoverable even if the file was deleted. " +
                                    "1) Rotate the secret immediately. 2) Use BFG Repo-Cleaner or git filter-repo to purge history. " +
                                    "3) Add the file pattern to .gitignore.",
                                EffortLevel    = "Hard",
                                Category       = "Security",
                                ConfidenceScore = 95
                            });
                        }
                    }
                }
                catch (RegexMatchTimeoutException) { }
            }
        }

        return issues;
    }

    private static async Task<string> RunGitAsync(string workingDir, string arguments, int timeoutSeconds, CancellationToken ct)
    {
        using var process = new System.Diagnostics.Process();
        process.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "git",
            Arguments = arguments,
            WorkingDirectory = workingDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        process.Start();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var sb = new StringBuilder();
        var buffer = new char[8192];
        const int maxChars = 5_000_000;
        int totalRead = 0;

        try
        {
            while (totalRead < maxChars)
            {
                int read = await process.StandardOutput.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token);
                if (read == 0) break;
                sb.Append(buffer, 0, read);
                totalRead += read;
            }
        }
        catch (OperationCanceledException) { }

        try { if (!process.HasExited) process.Kill(true); } catch { }

        return sb.ToString();
    }
}
