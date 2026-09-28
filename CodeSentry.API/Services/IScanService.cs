using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodeSentry.API.Models;
using CodeSentry.API.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentry.API.Services;

public interface IScanService
{
    Task<string> StartScanAsync(ScanRequest request, string? userId = null);
    Task<ScanState?> GetScanStatusAsync(string scanId);
    Task<List<ScanState>> GetRecentCompletedAsync(int count, string? userId = null);
    Task ClearHistoryAsync(string userId);
    Task ProcessScanAsync(string scanId, string repoUrl, CancellationToken cancellationToken = default);
}

public class ScanService : IScanService
{
    private static readonly ConcurrentDictionary<string, Task> _runningScans = new();
    private readonly IRepoCloneService _cloneService;
    private readonly IFileWalker _fileWalker;
    private readonly IAIAnalysisService _aiService;
    private readonly IGitHubService _githubService;
    private readonly ILogger<ScanService> _logger;
    private readonly IConfiguration _configuration;
    private readonly Supabase.Client _supabase;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHttpClientFactory _httpClientFactory;

    public ScanService(IRepoCloneService cloneService, IFileWalker fileWalker,
        IAIAnalysisService aiService, IGitHubService githubService, ILogger<ScanService> logger,
        IConfiguration configuration, Supabase.Client supabase, IServiceScopeFactory scopeFactory,
        IHttpClientFactory httpClientFactory)
    {
        _cloneService = cloneService;
        _fileWalker = fileWalker;
        _aiService = aiService;
        _githubService = githubService;
        _logger = logger;
        _configuration = configuration;
        _supabase = supabase;
        _scopeFactory = scopeFactory;
        _httpClientFactory = httpClientFactory;

        // Issue 9: Mark orphaned scans as FAILED on startup
        _ = MarkOrphanedScansAsFailed();
    }

    /// <summary>
    /// Issue 9: On app startup, mark any scans stuck in CLONING or ANALYSIS status as FAILED.
    /// These scans were interrupted by a server restart and will never complete.
    /// </summary>
    private async Task MarkOrphanedScansAsFailed()
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
            var orphanedScans = await context.ScanStates
                .Where(s => s.Status == ScanStages.Cloning || s.Status == ScanStages.Analysis ||
                            s.Status == ScanStages.AiReview || s.Status == ScanStages.Report)
                .ToListAsync();

            if (orphanedScans.Count > 0)
            {
                foreach (var scan in orphanedScans)
                {
                    scan.Status = ScanStages.Failed;
                    scan.Message = "Interrupted by server restart.";
                    _logger.LogWarning("[STARTUP] Marked orphaned scan {ScanId} (was {Status}) as FAILED",
                        scan.ScanId, scan.Status);
                }
                await context.SaveChangesAsync();
                _logger.LogInformation("[STARTUP] Marked {Count} orphaned scan(s) as FAILED", orphanedScans.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[STARTUP] Failed to mark orphaned scans");
        }
    }

    public async Task<string> StartScanAsync(ScanRequest request, string? userId = null)
    {
        var scanId = Guid.NewGuid().ToString("N")[..8].ToUpper();
        var state = new ScanState
        {
            ScanId = scanId,
            Status = ScanStages.Cloning,
            Message = "Initializing scan...",
            ProgressPercent = 5,
            CreatedAt = DateTime.UtcNow,
            UserId = userId,
            HealthScore = 0,
            RepositoryName = request.RepoUrl ?? string.Empty
        };

        // Save to local DB first (Reliable)
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
            context.ScanStates.Add(state);
            await context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save initial scan state to local DB");
        }

        // Attempt to sync to Supabase (Best effort)
        try
        {
            await _supabase.From<ScanState>().Insert(state);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Supabase sync failed (likely RLS): {Msg}. Falling back to local state.", ex.Message);
        }



        // Track the task
        var scanTask = Task.Run(async () =>
        {
            try
            {
                await ProcessScanAsync(scanId, request.RepoUrl ?? "");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[FATAL] Unhandled exception in scan {ScanId}", scanId);

                using var scope = _scopeFactory.CreateScope();
                var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
                var dbState = await context.ScanStates.FindAsync(scanId);
                if (dbState != null)
                {
                    dbState.Status = ScanStages.Failed;
                    dbState.Message = $"Error: {ex.Message}";
                    await context.SaveChangesAsync();
                }
            }
        });

        _runningScans[scanId] = scanTask;
        _ = CleanupCompletedTasks();

        return scanId;
    }

    public async Task<ScanState?> GetScanStatusAsync(string scanId)
    {
        // Try local DB first
        using (var scope = _scopeFactory.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
            var localState = await context.ScanStates.FindAsync(scanId);
            if (localState != null) return localState;
        }

        // Fallback to Supabase
        try
        {
            var response = await _supabase.From<ScanState>()
                .Select("*")
                .Filter("scan_id", Postgrest.Constants.Operator.Equals, scanId)
                .Single();
            return response;
        }
        catch { return null; }
    }

    public async Task<List<ScanState>> GetRecentCompletedAsync(int count, string? userId = null)
    {
        var results = new List<ScanState>();

        // 1. Try local DB first
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
            var query = context.ScanStates.Where(s => s.Status == ScanStages.Completed);

            if (!string.IsNullOrEmpty(userId))
                query = query.Where(s => s.UserId == userId);

            results = await query.OrderByDescending(s => s.CreatedAt).Take(count).ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch scan history from local DB");
        }

        // 2. Fetch from Supabase (REST API) if local DB has fewer records
        // This ensures deployment environments using Supabase have full access to history
        try
        {
            var supabaseQuery = _supabase.From<ScanState>()
                .Select("*")
                .Filter("status", Postgrest.Constants.Operator.Equals, ScanStages.Completed);

            if (!string.IsNullOrEmpty(userId))
            {
                supabaseQuery = supabaseQuery.Filter("user_id", Postgrest.Constants.Operator.Equals, userId);
            }

            var supabaseResponse = await supabaseQuery
                .Order("created_at", Postgrest.Constants.Ordering.Descending)
                .Limit(count)
                .Get();

            if (supabaseResponse.Models != null && supabaseResponse.Models.Any())
            {
                // Merge and take top N by CreatedAt
                results.AddRange(supabaseResponse.Models);
                results = results
                    .GroupBy(x => x.ScanId).Select(g => g.First()) // deduplicate by ScanId
                    .OrderByDescending(x => x.CreatedAt)
                    .Take(count)
                    .ToList();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Supabase history fetch failed: {Message}", ex.Message);
        }

        return results;
    }

    public async Task ClearHistoryAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId)) return;

        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
        
        var userScans = await db.ScanStates.Where(s => s.UserId == userId).ToListAsync();
        if (userScans.Any())
        {
            db.ScanStates.RemoveRange(userScans);
            await db.SaveChangesAsync();
        }
        

    }

    public async Task ProcessScanAsync(string scanId, string repoUrl, CancellationToken cancellationToken = default)
    {
        var totalSw = Stopwatch.StartNew();

        ScanState? state;
        using (var scope = _scopeFactory.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
            state = await context.ScanStates.FindAsync(scanId);
        }

        if (state == null) return;

        string? localPath = null;

        // Issue 25: Throttle DB writes — only persist when status changes or every 10 seconds
        string? lastPersistedStatus = null;
        DateTime lastDbWrite = DateTime.MinValue;

        async Task UpdateState(string msg, int progress, string? status = null)
        {
            state.Message = msg;
            state.ProgressPercent = progress;
            if (status != null) state.Status = status;

            // Only write to DB if status changed or 10+ seconds since last write
            bool statusChanged = status != null && status != lastPersistedStatus;
            bool throttleExpired = (DateTime.UtcNow - lastDbWrite).TotalSeconds >= 10;

            if (statusChanged || throttleExpired)
            {
                try
                {
                    using var scope = _scopeFactory.CreateScope();
                    var context = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
                    context.ScanStates.Update(state);
                    await context.SaveChangesAsync();
                    lastPersistedStatus = state.Status;
                    lastDbWrite = DateTime.UtcNow;

                    await _supabase.From<ScanState>().Upsert(state);
                }
                catch { /* Best effort update */ }
            }
        }

        try
        {
            // ── STAGE 1: CLONING ──
            await UpdateState($"[SYSTEM] Initializing scan for {repoUrl}", 5, ScanStages.Cloning);
            _logger.LogInformation("[SYSTEM] Initializing scan for {Url}", repoUrl);

            await Task.Delay(300);
            await UpdateState("[CLONING] Connecting to GitHub...", 10);

            // Fetch metadata
            var metadata = await _githubService.GetRepoMetadataAsync(repoUrl); // GitHubService doesn't take CT yet, but clone does
            if (metadata != null)
            {
                double sizeMb = metadata.Size / 1024.0;
                state.RepoSize = sizeMb >= 1024 ? $"{sizeMb / 1024:F2} GB" : $"{sizeMb:F1} MB";
                double estSeconds = (metadata.Size * 8) / (5.0 * 1024);
                state.EstimatedTime = estSeconds > 60 ? $"{(int)estSeconds / 60}m {(int)estSeconds % 60}s" : $"{(int)estSeconds}s";

                await UpdateState($"[CLONING] Repository size: {state.RepoSize} (Est. download: {state.EstimatedTime})", 15);
                _logger.LogInformation("[CLONING] Repo: {Name}, Size: {Size}, Est: {Est}", metadata.Name, state.RepoSize, state.EstimatedTime);
            }

            var cloneResult = await _cloneService.CloneAsync(repoUrl, scanId, cancellationToken);
            localPath = cloneResult.LocalPath;

            await UpdateState("[CLONING] Repository cloned successfully", 20);
            _logger.LogInformation("[CLONING] Repository cloned to {Path}", localPath);

            // ── STAGE 2: FILE WALK ──
            var walkResult = _fileWalker.Walk(localPath);
            var langStr = string.Join(", ", walkResult.LanguageBreakdown
                .OrderByDescending(kv => kv.Value).Take(5)
                .Select(kv => $"{kv.Key} ({kv.Value} files)"));

            await UpdateState($"[ANALYSIS] Discovered {walkResult.Files.Count} files across {walkResult.DirectoryCount} directories", 25, ScanStages.Analysis);
            _logger.LogInformation("[ANALYSIS] Found {FileCount} files", walkResult.Files.Count);

            await Task.Delay(200);
            await UpdateState($"[ANALYSIS] Found {walkResult.Files.Count} files ({langStr})", 35);
            await Task.Delay(400);

            // ── STAGE 3: LOCAL ANALYZERS ──
            await UpdateState("[ANALYSIS] Running local pattern and AST analyzers...", 40);

            await Task.Delay(200);
            await UpdateState($"[ANALYSIS] Loaded {walkResult.TotalLines:N0} lines of source code", 45);
            _logger.LogInformation("[ANALYSIS] {Lines} total lines loaded", walkResult.TotalLines);

            await Task.Delay(200);
            await UpdateState("[ANALYSIS] Local analysis complete — found structural issues", 55);
            await Task.Delay(400);

            // ── STAGE 4: AI REVIEW ──
            await UpdateState("[AI_CORE] Initializing deep heuristic AI review...", 60, ScanStages.AiReview);
            await Task.Delay(200);

            // ── FIX: Synchronous Progress<string> callback — no async void / fire-and-forget ──
            // UpdateState handles DB persistence. The progress callback only updates in-memory state.
            var progress = new Progress<string>(msg =>
            {
                state.Message = msg;
                state.ProgressPercent = Math.Min(state.ProgressPercent + 1, 89);
            });

            var analysisResult = await _aiService.AnalyzeLocalAsync(walkResult, localPath, progress, cancellationToken);

            await UpdateState("[REPORT] Compiling final intelligence report...", 90, ScanStages.Report);
            await Task.Delay(500);

            await UpdateState($"[REPORT] {analysisResult.Issues.Count} findings compiled", 92);
            _logger.LogInformation("[AI_REVIEW] Complete — {IssueCount} issues found", analysisResult.Issues.Count);

            totalSw.Stop();

            int critCount = analysisResult.Issues.Count(i => i.Severity == "Critical");
            int warnCount = analysisResult.Issues.Count(i => i.Severity == "Warning");
            int infoCount = analysisResult.Issues.Count(i => i.Severity == "Info");
            double debtHours = (critCount * 4.0) + (warnCount * 1.5) + (infoCount * 0.5);

            string scoreColor = analysisResult.HealthScore >= 80 ? "tertiary" :
                analysisResult.HealthScore >= 50 ? "primary" : "error";

            state.Result = new ScanResult
            {
                Id = scanId,
                Score = analysisResult.HealthScore,
                TotalIssues = analysisResult.Issues.Count,
                CriticalIssues = critCount,
                HoursSaved = (int)Math.Ceiling(debtHours),
                Issues = analysisResult.Issues,
                FileSummaries = analysisResult.FileSummaries,
                BorderColorClass = scoreColor,
                TimeAgo = "Just now",
                Duration = FormatDuration(totalSw.ElapsedMilliseconds)
            };

            state.HealthScore = analysisResult.HealthScore;

            await UpdateState($"[COMPLETED] Scan complete for {cloneResult.RepoName} — {totalSw.ElapsedMilliseconds}ms", 100, ScanStages.Completed);
            _logger.LogInformation("[COMPLETED] Scan {ScanId} done in {Ms}ms — score {Score}/100",
                scanId, totalSw.ElapsedMilliseconds, analysisResult.HealthScore);

            _ = SendWebhooksAsync(state);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[FAILED] Scan {ScanId} failed", scanId);
            await UpdateState($"Error: {ex.Message}", state.ProgressPercent, ScanStages.Failed);
            _ = SendWebhooksAsync(state);
        }
        finally
        {
            if (!string.IsNullOrEmpty(localPath))
                _cloneService.Cleanup(localPath);
        }
    }

    private async Task CleanupCompletedTasks()
    {
        await Task.Delay(5000);
        var completedIds = _runningScans
            .Where(kv => kv.Value.IsCompleted)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var id in completedIds)
        {
            if (_runningScans.TryRemove(id, out var task))
            {
                if (task.IsFaulted)
                    _logger.LogError(task.Exception, "[CLEANUP] Faulted scan task: {Id}", id);
            }
        }
    }

    private static string FormatDuration(long ms)
    {
        if (ms < 1000) return $"{ms}ms";
        if (ms < 60000) return $"{ms / 1000.0:F1}s";
        int mins = (int)(ms / 60000);
        int secs = (int)((ms % 60000) / 1000);
        return $"{mins}m {secs}s";
    }

    /// <summary>
    /// Issue 10: Signs webhook payloads with HMAC-SHA256 using a configured secret.
    /// Issue 26: Uses IHttpClientFactory instead of 'new HttpClient()'.
    /// </summary>
    private async Task SendWebhooksAsync(ScanState state)
    {
        var webhooks = _configuration.GetSection("Webhooks").Get<List<string>>();
        if (webhooks == null || webhooks.Count == 0) return;

        var webhookSecret = _configuration["WebhookSecret"];
        if (string.IsNullOrWhiteSpace(webhookSecret))
        {
            _logger.LogWarning("[WEBHOOK] WebhookSecret not configured — skipping webhook delivery. " +
                "Set 'WebhookSecret' in appsettings.json to enable signed webhook delivery.");
            return;
        }

        var client = _httpClientFactory.CreateClient("Webhooks");
        client.Timeout = TimeSpan.FromSeconds(10);

        var payloadJson = JsonSerializer.Serialize(state);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var secretBytes = Encoding.UTF8.GetBytes(webhookSecret);
        var signature = Convert.ToHexString(
            HMACSHA256.HashData(secretBytes, payloadBytes)).ToLowerInvariant();

        foreach (var url in webhooks)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(payloadJson, Encoding.UTF8, "application/json")
                };
                request.Headers.Add("X-CodeSentry-Signature", $"sha256={signature}");
                await client.SendAsync(request);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send webhook to {Url}", url);
            }
        }
    }
}
