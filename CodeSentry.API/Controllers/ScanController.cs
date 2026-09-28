using System.Collections.Concurrent;
using System.Security.Claims;
using CodeSentry.API.Data;
using CodeSentry.API.Models;
using CodeSentry.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CodeSentry.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ScanController : ControllerBase
{
    private readonly IScanService _scanService;
    private readonly IPdfReportService _pdfReportService;
    private readonly IPlanService _planService;
    private readonly ITechDebtService _techDebtService;
    private readonly IActionPlanService _actionPlanService;
    private readonly CodeSentryDbContext _context;

    // ── Rate limiting state ──
    // Max 3 concurrent active scans across all users
    private static readonly SemaphoreSlim _globalScanLimit = new(3, 3);
    // Max 1 concurrent scan per client IP
    private static readonly ConcurrentDictionary<string, int> _ipScanCounts = new();

    public ScanController(IScanService scanService, IPdfReportService pdfReportService, IPlanService planService, ITechDebtService techDebtService, IActionPlanService actionPlanService, CodeSentryDbContext context)
    {
        _scanService = scanService;
        _pdfReportService = pdfReportService;
        _planService = planService;
        _techDebtService = techDebtService;
        _actionPlanService = actionPlanService;
        _context = context;
    }

    /// <summary>
    /// Extracts the authenticated user's ID from the JWT "sub" claim.
    /// </summary>
    private string? GetUserId() =>
        User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");

    /// <summary>
    /// Verifies the authenticated user owns the specified scan.
    /// Returns null if authorized, or a 403 result if not.
    /// </summary>
    private IActionResult? CheckScanOwnership(ScanState scan)
    {
        var userId = GetUserId();
        // If scan has a UserId set, enforce ownership
        if (!string.IsNullOrEmpty(scan.UserId) && scan.UserId != userId)
        {
            return StatusCode(403, new { error = "You do not have access to this scan." });
        }
        return null;
    }

    [HttpPost("start")]
    public async Task<IActionResult> Start([FromBody] ScanRequest request)
    {
        if (string.IsNullOrEmpty(request.RepoUrl))
            return BadRequest("RepoUrl is required.");

        // ── RATE LIMIT: per-IP check (use Connection.RemoteIpAddress, never raw X-Forwarded-For) ──
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        var currentIpCount = _ipScanCounts.AddOrUpdate(clientIp, 1, (_, v) => v + 1);
        if (currentIpCount > 1)
        {
            // Revert increment back
            _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
            return StatusCode(429, new
            {
                error = "Maximum concurrent scans reached. Please wait.",
                detail = "Only 1 concurrent scan allowed per IP address."
            });
        }

        // ── RATE LIMIT: global concurrency check ──
        if (!_globalScanLimit.Wait(0))
        {
            // Revert IP counter
            _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
            return StatusCode(429, new
            {
                error = "Maximum concurrent scans reached. Please wait.",
                detail = "Server is at capacity (3 concurrent scans). Try again in a moment."
            });
        }

        // Attach authenticated user's ID to the scan request
        var userId = GetUserId();

        // ── PLAN ENFORCEMENT ──
        if (!string.IsNullOrEmpty(userId))
        {
            await _planService.ResetMonthlyCountIfNeeded(userId);
            var plan = await _planService.GetPlanAsync(userId);
            
            if (plan.PlanType == "FREE")
            {
                if (plan.ScansThisMonth >= 3)
                {
                    _globalScanLimit.Release();
                    _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
                    return StatusCode(429, new { error = "Free tier limit reached. Upgrade to Pro.", upgradeUrl = "/pricing" });
                }
                
                if (request.IsPrivate)
                {
                    _globalScanLimit.Release();
                    _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
                    return StatusCode(403, new { error = "Private repos require Pro or Team." });
                }
            }
        }

        string scanId;
        try
        {
            scanId = await _scanService.StartScanAsync(request, userId);
        }
        catch (ArgumentException ex)
        {
            // URL validation failures — bad request
            _globalScanLimit.Release();
            _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            _globalScanLimit.Release();
            _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
            return StatusCode(500, new { error = "Failed to start scan.", detail = ex.Message });
        }

        // Release resources when the scan finishes (fire-and-forget cleanup)
        _ = ReleaseScanSlotAsync(scanId, clientIp);

        if (!string.IsNullOrEmpty(userId))
        {
            await _planService.IncrementScanCount(userId);
        }

        return Ok(new { scanId });
    }

    [HttpGet("{scanId}/status")]
    public async Task<IActionResult> GetStatus(string scanId)
    {
        var status = await _scanService.GetScanStatusAsync(scanId);
        if (status == null)
            return NotFound("Scan not found");

        // SECURITY: Verify scan ownership
        var ownershipResult = CheckScanOwnership(status);
        if (ownershipResult != null) return ownershipResult;

        return Ok(new
        {
            scanId = status.ScanId,
            status = status.Status,
            message = status.Message,
            progressPercent = status.ProgressPercent,
            repoSize = status.RepoSize,
            estimatedTime = status.EstimatedTime,
            result = status.Result,
            createdAt = status.CreatedAt
        });
    }

    [HttpGet("{scanId}/report")]
    public async Task<IActionResult> GetReport(string scanId)
    {
        var status = await _scanService.GetScanStatusAsync(scanId);
        if (status == null || status.Status != ScanStages.Completed)
            return NotFound("Report not found or scan not completed");

        // SECURITY: Verify scan ownership
        var ownershipResult = CheckScanOwnership(status);
        if (ownershipResult != null) return ownershipResult;

        return Ok(status.Result);
    }

    [HttpGet("{scanId}/report/pdf")]
    public async Task<IActionResult> GetReportPdf(string scanId)
    {
        var userId = GetUserId();
        if (!string.IsNullOrEmpty(userId))
        {
            var plan = await _planService.GetPlanAsync(userId);
            if (plan.PlanType == "FREE")
            {
                return StatusCode(403, new { error = "PDF export is a Pro feature.", upgradeUrl = "/pricing" });
            }
        }

        var status = await _scanService.GetScanStatusAsync(scanId);
        if (status == null || status.Status != ScanStages.Completed || status.Result == null)
            return NotFound("Report not found or scan not completed");

        // SECURITY: Verify scan ownership
        var ownershipResult = CheckScanOwnership(status);
        if (ownershipResult != null) return ownershipResult;

        var pdfBytes = _pdfReportService.Generate(status);

        // SECURITY: Explicit MIME + Content-Disposition prevents MIME sniffing
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Content-Disposition"] = $"attachment; filename=\"codesentry-report-{scanId}.pdf\"";
        return File(pdfBytes, "application/pdf");
    }

    [HttpGet("{scanId}/action-plan")]
    public async Task<IActionResult> GetActionPlan(string scanId)
    {
        var scan = await _scanService.GetScanStatusAsync(scanId);
        if (scan == null) return NotFound("Scan not found");
        if (scan.Status != ScanStages.Completed || scan.Result?.Issues == null)
            return NotFound("Scan not completed or has no issues");

        // SECURITY: Verify scan ownership
        var ownershipResult = CheckScanOwnership(scan);
        if (ownershipResult != null) return ownershipResult;

        var actionItems = _actionPlanService.ComputeActionPlan(scan.Result.Issues);
        return Ok(actionItems);
    }

    [HttpGet("history")]
    public async Task<IActionResult> GetHistory()
    {
        var userId = GetUserId();
        var history = await _scanService.GetRecentCompletedAsync(10, userId);
        var recentScans = history.Select(s => new
        {
            Id = s.ScanId,
            TimeAgo = s.Result?.TimeAgo ?? "Unknown",
            Score = s.Result?.Score ?? 0,
            Status = s.Status,
            BorderColorClass = s.Result?.BorderColorClass ?? "primary",
            CreatedAt = s.CreatedAt,
            RepositoryName = !string.IsNullOrEmpty(s.RepositoryName) ? s.RepositoryName : s.ScanId
        }).ToList();

        return Ok(recentScans);
    }

    [HttpDelete("history")]
    public async Task<IActionResult> ClearHistory()
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();
        
        await _scanService.ClearHistoryAsync(userId);
        return Ok();
    }

    [HttpGet("logs/{scanId}")]
    public async Task<IActionResult> GetLogs(string scanId)
    {
        var status = await _scanService.GetScanStatusAsync(scanId);
        if (status == null)
            return NotFound("Scan not found");

        // SECURITY: Verify scan ownership
        var ownershipResult = CheckScanOwnership(status);
        if (ownershipResult != null) return ownershipResult;

        var logs = new List<object>();
        var createdAt = status.CreatedAt;

        if (status.Status == ScanStages.Completed || status.Status == ScanStages.Report)
        {
            logs.Add(new { Time = createdAt.AddSeconds(1).ToString("HH:mm:ss.fff"), Type = "SYSTEM",    Message = "Scan initiated",                          TextColorClass = "primary" });
            logs.Add(new { Time = createdAt.AddSeconds(3).ToString("HH:mm:ss.fff"), Type = "CLONING",   Message = "Repository cloned successfully",           TextColorClass = "tertiary" });
            logs.Add(new { Time = createdAt.AddSeconds(5).ToString("HH:mm:ss.fff"), Type = "ANALYSIS",  Message = "Static code review in progress...",        TextColorClass = "on-surface-variant" });
            logs.Add(new { Time = createdAt.AddSeconds(10).ToString("HH:mm:ss.fff"), Type = "AI_CORE",  Message = "Deep heuristic AI review running...",      TextColorClass = "primary" });
            logs.Add(new { Time = createdAt.AddSeconds(15).ToString("HH:mm:ss.fff"), Type = "COMPLETED",Message = $"Scan complete — Score: {status.Result?.Score}/100", TextColorClass = "tertiary" });
        }
        else
        {
            logs.Add(new { Time = createdAt.ToString("HH:mm:ss.fff"), Type = "SYSTEM", Message = status.Message ?? "Processing...", TextColorClass = "primary" });
        }

        return Ok(logs);
    }

    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        var userId = GetUserId();
        var history = await _scanService.GetRecentCompletedAsync(100, userId);

        int totalScans    = history.Count;
        int avgScore      = history.Count > 0 ? history.Sum(s => s.Result?.Score ?? 0) / history.Count : 0;
        int totalIssues   = history.Sum(s => s.Result?.TotalIssues ?? 0);
        int criticalIssues = history.Sum(s => s.Result?.CriticalIssues ?? 0);

        double techDebtHours = 0;
        foreach (var scan in history)
        {
            if (scan.Result?.Issues != null)
            {
                techDebtHours += scan.Result.Issues.Count(i => i.Severity == "Critical") * 4.0;
                techDebtHours += scan.Result.Issues.Count(i => i.Severity == "Warning") * 1.5;
                techDebtHours += scan.Result.Issues.Count(i => i.Severity == "Info") * 0.5;
            }
        }
        
        decimal techDebtDollars = _techDebtService.ConvertToDollarCost(techDebtHours);

        return Ok(new { totalScans, avgScore, totalIssues, criticalIssues, techDebtHours = (int)techDebtHours, techDebtDollars });
    }

    /// <summary>
    /// Deletes a scan owned by the authenticated user.
    /// Demonstrates CRUD — Delete operation.
    /// </summary>
    [HttpDelete("{scanId}")]
    public async Task<IActionResult> DeleteScan(string scanId)
    {
        var userId = GetUserId();
        var scan   = await _context.ScanStates.FindAsync(scanId);

        if (scan == null)
            return NotFound(new { error = "Scan not found." });

        // Ownership check — only the owner may delete their own scan
        if (!string.IsNullOrEmpty(scan.UserId) && scan.UserId != userId)
            return StatusCode(403, new { error = "You do not have permission to delete this scan." });

        _context.ScanStates.Remove(scan);
        await _context.SaveChangesAsync();

        return Ok(new { message = $"Scan {scanId} deleted successfully." });
    }

    /// <summary>
    /// Polls until the scan finishes (completed or failed), then releases global + per-IP slots.
    /// </summary>
    private async Task ReleaseScanSlotAsync(string scanId, string clientIp)
    {
        try
        {
            for (var i = 0; i < 600; i++) // max 10 minutes
            {
                await Task.Delay(1000);
                var state = await _scanService.GetScanStatusAsync(scanId);
                if (state == null) break;
                if (state.Status == ScanStages.Completed || state.Status == ScanStages.Failed) break;
            }
        }
        finally
        {
            _globalScanLimit.Release();
            _ipScanCounts.AddOrUpdate(clientIp, 0, (_, v) => Math.Max(0, v - 1));
        }
    }
}