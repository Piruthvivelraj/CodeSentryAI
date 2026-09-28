using System.Security.Claims;
using CodeSentry.API.Models;
using CodeSentry.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CodeSentry.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class RepoController : ControllerBase
{
    private readonly IScanService _scanService;

    public RepoController(IScanService scanService)
    {
        _scanService = scanService;
    }

    [HttpGet("recent")]
    public async Task<IActionResult> GetRecentRepos()
    {
        // SECURITY: Only return scans belonging to the authenticated user
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        var completed = await _scanService.GetRecentCompletedAsync(10, userId);

        if (completed.Count == 0)
        {
            return Ok(new List<Repository>());
        }

        var repos = completed.Select(s =>
        {
            var score = s.Result?.Score ?? 0;
            var colorClass = score >= 80 ? "tertiary" : score >= 50 ? "primary" : "error";
            var status     = score >= 80 ? "HEALTHY"  : score >= 50 ? "NOMINAL" : "CRITICAL";
            var criticals  = s.Result?.Issues?.Count(i => i.Severity == "Critical") ?? 0;
            var warnings   = s.Result?.Issues?.Count(i => i.Severity == "Warning")  ?? 0;

            // Use RepositoryName if set, else fallback to the last part of ScanId
            var repoName = !string.IsNullOrEmpty(s.RepositoryName)
                ? s.RepositoryName
                : s.ScanId;

            return new Repository
            {
                Id            = s.ScanId,
                Name          = repoName,
                LastScan      = s.Result?.TimeAgo ?? "Unknown",
                Coverage      = score,
                Status        = status,
                StatusColorClass = colorClass,
                CriticalCount = criticals,
                WarningCount  = warnings
            };
        }).ToList();

        return Ok(repos);
    }
}
