using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// FORENSIC ATTRIBUTION ENGINE — uses git blame to attribute every single finding
/// to the exact developer, commit, and timestamp that introduced it.
/// This transforms CodeSentry from a static scanner into a forensic accountability tool.
/// </summary>
public static class GitAttributionAnalyzer
{
    private static readonly Regex BlameHashRx = new(@"^([a-f0-9]{40})\s+\d+\s+\d+(", RegexOptions.Compiled);
    private static readonly Regex AuthorRx = new(@"^author\s+(.+)$", RegexOptions.Compiled);
    private static readonly Regex AuthorMailRx = new(@"^author-mail\s+<(.+)>$", RegexOptions.Compiled);
    private static readonly Regex AuthorTimeRx = new(@"^author-time\s+(\d+)$", RegexOptions.Compiled);
    private static readonly Regex SummaryRx = new(@"^summary\s+(.+)$", RegexOptions.Compiled);

    /// <summary>
    /// Enriches all issues with git blame metadata. Groups by (file,line) to minimize git calls.
    /// </summary>
    public static async Task EnrichAsync(List<CodeIssue> issues, string repoRoot)
    {
        if (issues.Count == 0) return;

        // Group issues by unique (file, line) to avoid redundant blame calls
        var groups = issues
            .Where(i => i.LineNumber > 0 && !string.IsNullOrEmpty(i.FilePath) && !i.FilePath.StartsWith(".git/"))
            .GroupBy(i => (i.FilePath, i.LineNumber))
            .ToList();

        // Concurrent dictionary for caching blame results
        var cache = new ConcurrentDictionary<(string File, int Line), BlameResult>();

        var semaphore = new SemaphoreSlim(4); // Max 4 concurrent processes
        var tasks = groups.Select(async g =>
        {
            await semaphore.WaitAsync();
            try
            {
                var result = await RunBlameAsync(repoRoot, g.Key.FilePath, g.Key.LineNumber);
                if (result != null)
                    cache[g.Key] = result;
            }
            catch { /* Non-fatal: attribution is best-effort */ }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);

        // Apply cached attribution back to all issues
        foreach (var issue in issues)
        {
            if (issue.LineNumber <= 0 || string.IsNullOrEmpty(issue.FilePath)) continue;
            if (issue.FilePath.StartsWith(".git/")) continue; // Skip git-internal issues

            if (cache.TryGetValue((issue.FilePath, issue.LineNumber), out var blame))
            {
                issue.CommitHash = blame.Hash;
                issue.Author = blame.Author;
                issue.AuthorEmail = blame.AuthorEmail;
                issue.CommitDate = blame.Date;
                issue.CommitMessage = blame.Summary;
                issue.IntroducedBy = $"{blame.Author} in {blame.Hash[..7]} ({blame.Date})";
            }
        }
    }

    private static async Task<BlameResult?> RunBlameAsync(string repoRoot, string file, int line)
    {
        string output;
        try
        {
            output = await RepoCloneService.RunProcessAsync("git", new[] { "blame", "-L", $"{line},{line}", "--porcelain", "--", file }, repoRoot, 10, CancellationToken.None);
        }
        catch
        {
            return null;
        }

        string hash = "", author = "", email = "", summary = "";
        string date = "unknown";

        foreach (var raw in output.Split('\n'))
        {
            var l = raw.TrimEnd();

            var hm = BlameHashRx.Match(l);
            if (hm.Success) { hash = hm.Groups[1].Value; continue; }

            var am = AuthorRx.Match(l);
            if (am.Success) { author = am.Groups[1].Value.Trim(); continue; }

            var em = AuthorMailRx.Match(l);
            if (em.Success) { email = em.Groups[1].Value.Trim(); continue; }

            var tm = AuthorTimeRx.Match(l);
            if (tm.Success && long.TryParse(tm.Groups[1].Value, out var unixSec))
            {
                date = DateTimeOffset.FromUnixTimeSeconds(unixSec).UtcDateTime.ToString("yyyy-MM-dd HH:mm UTC");
                continue;
            }

            var sm = SummaryRx.Match(l);
            if (sm.Success) { summary = sm.Groups[1].Value.Trim(); continue; }
        }

        if (string.IsNullOrEmpty(hash)) return null;

        return new BlameResult
        {
            Hash = hash,
            Author = author,
            AuthorEmail = email,
            Date = date,
            Summary = summary
        };
    }

    private class BlameResult
    {
        public string Hash { get; set; } = "";
        public string Author { get; set; } = "";
        public string AuthorEmail { get; set; } = "";
        public string Date { get; set; } = "";
        public string Summary { get; set; } = "";
    }
}
