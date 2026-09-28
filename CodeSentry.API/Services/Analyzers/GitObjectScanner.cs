using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// DEEPEST POSSIBLE GIT SCAN — analyzes raw git object database, dangling blobs, unreachable commits,
/// reflog entries, orphaned objects, pack files, .git/config credentials, hooks, and stashes.
/// This is the forensic layer that almost NO static analysis tool implements comprehensively.
/// </summary>
public static class GitObjectScanner
{
    // Secret patterns for raw blob analysis
    private static readonly Regex SecretPattern = new(
        @"(password|passwd|secret|secret_key|api_key|apikey|token|auth_token|access_token|private_key)\s*[=:]\s*['""][^'""]{8,}['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(500));

    private static readonly Regex JwtPattern = new(
        @"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        RegexOptions.Compiled);

    private static readonly Regex AwsKeyPattern = new(
        @"AKIA[0-9A-Z]{16}", RegexOptions.Compiled);

    private static readonly Regex StripeKeyPattern = new(
        @"(sk_live_|pk_live_)[a-zA-Z0-9]{24,}", RegexOptions.Compiled);

    private static readonly Regex GenericHighEntropy = new(
        @"\b[a-zA-Z0-9_\-]{32,64}\b", RegexOptions.Compiled);

    public static async Task<List<CodeIssue>> AnalyzeAsync(string repoRoot, CancellationToken ct = default)
    {
        var issues = new List<CodeIssue>();

        // ── 1. RAW OBJECT DATABASE SCAN ──
        issues.AddRange(await ScanUnreachableObjectsAsync(repoRoot, ct));

        // ── 2. REFLOG FORENSICS ──
        issues.AddRange(await ScanReflogAsync(repoRoot, ct));

        // ── 3. STASH ANALYSIS ──
        issues.AddRange(await ScanStashesAsync(repoRoot, ct));

        // ── 4. .git/CONFIG CREDENTIAL SCAN ──
        issues.AddRange(ScanGitConfig(repoRoot));

        // ── 5. HOOK FORENSICS ──
        issues.AddRange(ScanHooks(repoRoot));

        // ── 6. SUBMODULE SECURITY ──
        issues.AddRange(ScanSubmodules(repoRoot));

        // ── 7. PACK FILE LEAK CHECK ──
        issues.AddRange(await ScanPackFilesAsync(repoRoot, ct));

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 1. UNREACHABLE OBJECTS — the deepest forensic layer
    // ═══════════════════════════════════════════════════════════════════
    private static async Task<List<CodeIssue>> ScanUnreachableObjectsAsync(string repoRoot, CancellationToken ct)
    {
        var issues = new List<CodeIssue>();

        try
        {
            // Get ALL unreachable objects: dangling commits, blobs, trees
            var fsckOutput = await RunGitAsync(repoRoot,
                "fsck --unreachable --no-reflogs --dangling", 60, ct);

            var unreachableObjects = ParseFsckOutput(fsckOutput);

            // Batch process: for each dangling blob, cat-file and scan
            var blobObjects = unreachableObjects
                .Where(o => o.Type == "blob")
                .Take(500) // Cap to prevent abuse
                .ToList();

            var seenHashes = new HashSet<string>();

            await Parallel.ForEachAsync(blobObjects, new ParallelOptions
            {
                MaxDegreeOfParallelism = 4,
                CancellationToken = ct
            }, async (obj, innerCt) =>
            {
                try
                {
                    var content = await RunGitAsync(repoRoot, $"cat-file -p {obj.Hash}", 10, innerCt);
                    if (string.IsNullOrWhiteSpace(content)) return;

                    var localIssues = ScanContentForSecrets(content, obj.Hash, $"[DANGLING BLOB {obj.Hash}]");
                    lock (issues)
                    {
                        foreach (var issue in localIssues)
                        {
                            if (seenHashes.Add($"{obj.Hash}:{issue.Title}"))
                                issues.Add(issue);
                        }
                    }
                }
                catch { /* Individual blob failures are non-fatal */ }
            });

            // Check unreachable commits for hidden file additions
            var commitObjects = unreachableObjects
                .Where(o => o.Type == "commit")
                .Take(200)
                .ToList();

            foreach (var commit in commitObjects)
            {
                try
                {
                    var diffOutput = await RunGitAsync(repoRoot,
                        $"show --stat --format=\"\" {commit.Hash}", 15, ct);

                    if (diffOutput.Contains(".env") || diffOutput.Contains("config") ||
                        diffOutput.Contains("secret") || diffOutput.Contains("password"))
                    {
                        lock (issues)
                        {
                            issues.Add(new CodeIssue
                            {
                                Severity = "Warning",
                                Title = "Unreachable Commit Contains Sensitive Files",
                                Description = $"Unreachable commit {commit.Hash} modified files that appear to contain secrets/configuration. " +
                                    "This commit is not reachable from any branch but still exists in the object database and can be recovered.",
                                FilePath = $".git/objects/{commit.Hash[..2]}/{commit.Hash[2..]}",
                                LineNumber = 0,
                                Suggestion = "Purge unreachable commits using 'git reflog expire --expire-unreachable=now --all' followed by 'git gc --prune=now'.",
                                EffortLevel = "Hard",
                                Category = "Security",
                                ConfidenceScore = 80,
                                ReachabilityStatus = "UnreachableCommit"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WARN] GitObjectScanner (unreachable) failed: {ex.Message}");
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 2. REFLOG — forensic timeline of every ref mutation
    // ═══════════════════════════════════════════════════════════════════
    private static async Task<List<CodeIssue>> ScanReflogAsync(string repoRoot, CancellationToken ct)
    {
        var issues = new List<CodeIssue>();

        try
        {
            // Get reflog for ALL refs
            var reflogOutput = await RunGitAsync(repoRoot, "reflog --all --format=\"%H|%gd|%gs|%ci\"", 60, ct);

            var lines = reflogOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var seenCommits = new HashSet<string>();

            foreach (var line in lines.Take(500))
            {
                var parts = line.Split('|', 4);
                if (parts.Length < 4) continue;

                var hash = parts[0];
                var reflogEntry = parts[1];
                var action = parts[2];
                var date = parts[3];

                if (!seenCommits.Add(hash)) continue;

                // Check if commit message contains secret keywords
                try
                {
                    var msg = await RunGitAsync(repoRoot, $"log -1 --format=%B {hash}", 10, ct);
                    if (msg.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("key", StringComparison.OrdinalIgnoreCase))
                    {
                        issues.Add(new CodeIssue
                        {
                            Severity = "Warning",
                            Title = "Sensitive Keyword in Commit Message",
                            Description = $"Commit {hash[..7]} (reflog entry {reflogEntry}, {date}) has a message containing sensitive keywords. " +
                                "Commit messages are permanently retained and may leak context about secrets.",
                            FilePath = $".git/logs/refs/{reflogEntry.TrimStart('@').Replace("{", "").Replace("}", "")}",
                            LineNumber = 0,
                            Suggestion = "Amend the commit message using interactive rebase or filter-repo. Be aware this rewrites history.",
                            EffortLevel = "Hard",
                            Category = "Security",
                            ConfidenceScore = 55,
                            CommitHash = hash,
                            CommitDate = date,
                            ReachabilityStatus = "ReflogEntry"
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WARN] GitObjectScanner (reflog) failed: {ex.Message}");
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 3. STASH ANALYSIS — secrets hidden in git stash
    // ═══════════════════════════════════════════════════════════════════
    private static async Task<List<CodeIssue>> ScanStashesAsync(string repoRoot, CancellationToken ct)
    {
        var issues = new List<CodeIssue>();

        try
        {
            var stashList = await RunGitAsync(repoRoot, "stash list --format=\"%H|%gd|%s\"", 15, ct);
            var stashes = stashList.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var stash in stashes.Take(20))
            {
                var parts = stash.Split('|', 3);
                if (parts.Length < 3) continue;

                var hash = parts[0];
                var refName = parts[1];
                var message = parts[2];

                // Diff the stash against its parent
                var diffOutput = await RunGitAsync(repoRoot, $"stash show -p {refName}", 15, ct);
                var secretIssues = ScanContentForSecrets(diffOutput, hash, $"[STASH {refName}]");

                foreach (var issue in secretIssues)
                {
                    issue.Title = $"Secret in Git Stash: {issue.Title}";
                    issue.ReachabilityStatus = "Stash";
                    issue.CommitHash = hash;
                    issues.Add(issue);
                }

                // Also check stash message
                if (message.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("secret", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new CodeIssue
                    {
                        Severity = "Warning",
                        Title = "Sensitive Git Stash Message",
                        Description = $"Git stash {refName} has a message containing sensitive keywords: '{message}'.",
                        FilePath = ".git/logs/refs/stash",
                        LineNumber = 0,
                        Suggestion = "Drop the stash with 'git stash drop {refName}' if it contains secrets, or amend if possible.",
                        EffortLevel = "Easy",
                        Category = "Security",
                        ConfidenceScore = 65,
                        CommitHash = hash,
                        ReachabilityStatus = "Stash"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WARN] GitObjectScanner (stash) failed: {ex.Message}");
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 4. .git/config CREDENTIAL EXPOSURE
    // ═══════════════════════════════════════════════════════════════════
    private static List<CodeIssue> ScanGitConfig(string repoRoot)
    {
        var issues = new List<CodeIssue>();
        var configPath = Path.Combine(repoRoot, ".git", "config");

        if (!File.Exists(configPath)) return issues;

        try
        {
            var content = File.ReadAllText(configPath);
            var lines = content.Split('\n');

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];

                // Embedded credentials in remote URL
                if (line.Contains("url = ", StringComparison.OrdinalIgnoreCase) &&
                    (line.Contains('@') || line.Contains("://")))
                {
                    if (line.Contains("://") && line.Contains('@'))
                    {
                        var urlMatch = Regex.Match(line, @"url\s*=\s*(.+)", RegexOptions.IgnoreCase);
                        if (urlMatch.Success)
                        {
                            var url = urlMatch.Groups[1].Value.Trim();
                            if (url.Contains(":") && url.Contains("@"))
                            {
                                issues.Add(new CodeIssue
                                {
                                    Severity = "Critical",
                                    Title = "Git Remote URL Contains Embedded Credentials",
                                    Description = $"Remote URL contains username/password: {MaskUrl(url)}. " +
                                        "These credentials are stored in plaintext in .git/config.",
                                    FilePath = ".git/config",
                                    LineNumber = i + 1,
                                    Suggestion = "Remove credentials from the remote URL. Use SSH keys, credential helpers, or environment variables instead.",
                                    EffortLevel = "Easy",
                                    Category = "Security",
                                    ConfidenceScore = 100,
                                    ReachabilityStatus = "Active"
                                });
                            }
                        }
                    }

                    // HTTP instead of HTTPS
                    if (line.Contains("http://", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("localhost") && !line.Contains("127.0.0.1"))
                    {
                        issues.Add(new CodeIssue
                        {
                            Severity = "Warning",
                            Title = "Insecure HTTP Git Remote",
                            Description = "Git remote is configured to use HTTP instead of HTTPS. " +
                                "All git operations (including push with credentials) are sent in plaintext.",
                            FilePath = ".git/config",
                            LineNumber = i + 1,
                            Suggestion = "Change remote URL to HTTPS or SSH. Run: git remote set-url origin <https-url>",
                            EffortLevel = "Easy",
                            Category = "Security",
                            ConfidenceScore = 95,
                            ReachabilityStatus = "Active"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WARN] GitObjectScanner (config) failed: {ex.Message}");
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 5. HOOK FORENSICS — malicious or overly permissive hooks
    // ═══════════════════════════════════════════════════════════════════
    private static List<CodeIssue> ScanHooks(string repoRoot)
    {
        var issues = new List<CodeIssue>();
        var hooksDir = Path.Combine(repoRoot, ".git", "hooks");

        if (!Directory.Exists(hooksDir)) return issues;

        var standardHooks = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update",
            "pre-applypatch", "pre-commit", "pre-merge-commit", "pre-push",
            "pre-rebase", "pre-receive", "prepare-commit-msg", "push-to-checkout",
            "update", "pre-auto-gc"
        };

        foreach (var hook in Directory.GetFiles(hooksDir))
        {
            var name = Path.GetFileName(hook);
            var isStandard = standardHooks.Contains(name);
            var isExecutable = (File.GetAttributes(hook) & FileAttributes.ReadOnly) == 0; // Rough check on Windows
            var content = File.ReadAllText(hook);

            // Non-standard hook
            if (!isStandard)
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Warning",
                    Title = "Non-Standard Git Hook Detected",
                    Description = $"Git hook '{name}' is not a standard hook name. This could be a persistence mechanism.",
                    FilePath = $".git/hooks/{name}",
                    LineNumber = 0,
                    Suggestion = "Review all non-standard hooks. Malicious actors sometimes add custom hooks for persistence.",
                    EffortLevel = "Easy",
                    Category = "Security",
                    ConfidenceScore = 70,
                    ReachabilityStatus = "Active"
                });
            }

            // Hook contains suspicious commands
            var lowerContent = content.ToLowerInvariant();
            if (lowerContent.Contains("curl") || lowerContent.Contains("wget") ||
                lowerContent.Contains("nc ") || lowerContent.Contains("netcat") ||
                lowerContent.Contains("bash -i") || lowerContent.Contains("/dev/tcp/") ||
                lowerContent.Contains("password") || lowerContent.Contains("secret") ||
                lowerContent.Contains("token"))
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Critical",
                    Title = $"Potentially Malicious Git Hook: {name}",
                    Description = $"Git hook '{name}' contains suspicious commands or secret keywords. " +
                        "Malicious hooks can exfiltrate code, steal credentials, or establish backdoors.",
                    FilePath = $".git/hooks/{name}",
                    LineNumber = 0,
                    Suggestion = "Immediately inspect this hook. If you did not create it, remove it and rotate all credentials.",
                    EffortLevel = "Easy",
                    Category = "Security",
                    ConfidenceScore = 90,
                    ReachabilityStatus = "Active"
                });
            }
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 6. SUBMODULE SECURITY
    // ═══════════════════════════════════════════════════════════════════
    private static List<CodeIssue> ScanSubmodules(string repoRoot)
    {
        var issues = new List<CodeIssue>();
        var modulesPath = Path.Combine(repoRoot, ".gitmodules");

        if (!File.Exists(modulesPath)) return issues;

        try
        {
            var content = File.ReadAllText(modulesPath);
            var lines = content.Split('\n');

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];

                if (line.Contains("url = ", StringComparison.OrdinalIgnoreCase))
                {
                    if (line.Contains("http://", StringComparison.OrdinalIgnoreCase))
                    {
                        issues.Add(new CodeIssue
                        {
                            Severity = "Warning",
                            Title = "Submodule Using Insecure HTTP",
                            Description = "Git submodule is configured with HTTP instead of HTTPS. " +
                                "Submodules can be MITM-attacked during clone/fetch operations.",
                            FilePath = ".gitmodules",
                            LineNumber = i + 1,
                            Suggestion = "Change submodule URL to HTTPS or SSH in .gitmodules and run: git submodule sync",
                            EffortLevel = "Easy",
                            Category = "Security",
                            ConfidenceScore = 90,
                            ReachabilityStatus = "Active"
                        });
                    }

                    if (line.Contains('@') && line.Contains("://"))
                    {
                        issues.Add(new CodeIssue
                        {
                            Severity = "Critical",
                            Title = "Submodule URL Contains Embedded Credentials",
                            Description = "Submodule URL contains embedded username/password. " +
                                "These credentials are committed to version control.",
                            FilePath = ".gitmodules",
                            LineNumber = i + 1,
                            Suggestion = "Remove credentials from submodule URL. Use SSH or credential helpers.",
                            EffortLevel = "Medium",
                            Category = "Security",
                            ConfidenceScore = 100,
                            ReachabilityStatus = "Active"
                        });
                    }
                }

                // Relative path traversal in submodule
                if (line.Contains("path = ..", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new CodeIssue
                    {
                        Severity = "Critical",
                        Title = "Submodule Path Traversal",
                        Description = "Submodule path traverses outside the repository root. " +
                            "This is a known attack vector (CVE-2018-11235).",
                        FilePath = ".gitmodules",
                        LineNumber = i + 1,
                        Suggestion = "Ensure all submodule paths are within the repository. Never use '../' in submodule paths.",
                        EffortLevel = "Easy",
                        Category = "Security",
                        ConfidenceScore = 100,
                        ReachabilityStatus = "Active"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WARN] GitObjectScanner (submodules) failed: {ex.Message}");
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // 7. PACK FILE LEAK CHECK — Check pack index for orphaned secrets
    // ═══════════════════════════════════════════════════════════════════
    private static async Task<List<CodeIssue>> ScanPackFilesAsync(string repoRoot, CancellationToken ct)
    {
        var issues = new List<CodeIssue>();

        try
        {
            var packDir = Path.Combine(repoRoot, ".git", "objects", "pack");
            if (!Directory.Exists(packDir)) return issues;

            var idxFiles = Directory.GetFiles(packDir, "*.idx");
            if (idxFiles.Length == 0) return issues;

            var largeObjects = new List<(string Hash, long Size)>();

            foreach (var idxFile in idxFiles)
            {
                var relativeIdxPath = Path.Combine(".git", "objects", "pack", Path.GetFileName(idxFile));
                // Run git verify-pack on each concrete index file individually and safely
                var packOutput = await RunGitAsync(repoRoot, $"verify-pack -v {relativeIdxPath}", 30, ct);

                if (!string.IsNullOrWhiteSpace(packOutput))
                {
                    foreach (var line in packOutput.Split('\n'))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 3 && long.TryParse(parts[2], out var size) && size > 10 * 1024 * 1024)
                        {
                            largeObjects.Add((parts[0], size));
                        }
                    }
                }
            }

            foreach (var (hash, size) in largeObjects.Take(5))
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Info",
                    Title = "Large Object in Pack File",
                    Description = $"Pack file contains a {size / (1024 * 1024)}MB object ({hash}). " +
                        "Large objects in pack files may contain committed database dumps, logs, or binary secrets.",
                    FilePath = ".git/objects/pack/",
                    LineNumber = 0,
                    Suggestion = "Investigate the object with 'git cat-file -p <hash>'. If it's sensitive, purge it from history.",
                    EffortLevel = "Hard",
                    Category = "Structure",
                    ConfidenceScore = 40,
                    ReachabilityStatus = "Active"
                });
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WARN] GitObjectScanner (pack) failed: {ex.Message}");
        }

        return issues;
    }

    // ═══════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════

    private static List<CodeIssue> ScanContentForSecrets(string content, string hash, string prefix)
    {
        var issues = new List<CodeIssue>();
        var lines = content.Split('\n');
        var seen = new HashSet<string>();

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;

            // Check secret patterns
            foreach (Match m in SecretPattern.Matches(line))
            {
                var key = $"{hash}:{i}:{m.Value}";
                if (!seen.Add(key)) continue;

                issues.Add(new CodeIssue
                {
                    Severity = "Critical",
                    Title = $"{prefix} Secret Found in Raw Git Object",
                    Description = $"{prefix} Secret pattern matched in raw git object content. " +
                        "This object may be dangling, unreachable, or part of reflog/stash history.",
                    FilePath = $".git/objects/{hash[..2]}/{hash[2..]}",
                    LineNumber = i + 1,
                    Suggestion = "Purge this object from git history using BFG Repo-Cleaner or git filter-repo. Then rotate the secret.",
                    EffortLevel = "Hard",
                    Category = "Security",
                    ConfidenceScore = 95,
                    CommitHash = hash,
                    ReachabilityStatus = "DanglingBlob"
                });
            }

            // JWT
            foreach (Match m in JwtPattern.Matches(line))
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Critical",
                    Title = $"{prefix} JWT Token in Raw Git Object",
                    Description = $"JWT token found in raw git object {hash}.",
                    FilePath = $".git/objects/{hash[..2]}/{hash[2..]}",
                    LineNumber = i + 1,
                    Suggestion = "JWT tokens in git history are permanently exposed. Rotate the signing key immediately.",
                    EffortLevel = "Hard",
                    Category = "Security",
                    ConfidenceScore = 95,
                    CommitHash = hash,
                    ReachabilityStatus = "DanglingBlob"
                });
            }

            // AWS key
            foreach (Match m in AwsKeyPattern.Matches(line))
            {
                issues.Add(new CodeIssue
                {
                    Severity = "Critical",
                    Title = $"{prefix} AWS Key in Raw Git Object",
                    Description = $"AWS access key found in raw git object {hash}.",
                    FilePath = $".git/objects/{hash[..2]}/{hash[2..]}",
                    LineNumber = i + 1,
                    Suggestion = "Rotate this AWS IAM key immediately via the AWS console.",
                    EffortLevel = "Hard",
                    Category = "Security",
                    ConfidenceScore = 98,
                    CommitHash = hash,
                    ReachabilityStatus = "DanglingBlob"
                });
            }
        }

        return issues;
    }

    private static List<(string Hash, string Type)> ParseFsckOutput(string output)
    {
        var results = new List<(string, string)>();
        foreach (var line in output.Split('\n'))
        {
            // Format: "unreachable blob abc123..." or "dangling commit def456..."
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3 && (parts[0] == "unreachable" || parts[0] == "dangling"))
            {
                results.Add((parts[2], parts[1]));
            }
        }
        return results;
    }

    private static string MaskUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                return uri.Scheme + "://***:***@" + uri.Host + uri.PathAndQuery;
            }
        }
        catch { }
        return url;
    }

    private static async Task<string> RunGitAsync(string workingDir, string arguments, int timeoutSeconds, CancellationToken ct)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
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
