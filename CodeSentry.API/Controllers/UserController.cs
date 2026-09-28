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
public class UserController : ControllerBase
{
    private readonly CodeSentryDbContext _context;
    private readonly IPlanService _planService;

    public UserController(CodeSentryDbContext context, IPlanService planService)
    {
        _context = context;
        _planService = planService;
    }

    private string? GetUserId() =>
        User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");

    [HttpPatch("profile")]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var user = await _context.LocalUsers.FindAsync(userId);
        if (user == null)
        {
            // PlanService auto-upserts users on first access, but just in case
            user = new LocalUser { SupabaseId = userId, Email = User.FindFirstValue(ClaimTypes.Email) ?? "unknown" };
            _context.LocalUsers.Add(user);
        }

        user.DisplayName = request.DisplayName ?? "";
        await _context.SaveChangesAsync();

        return Ok(new { user.DisplayName });
    }

    [HttpGet("plan")]
    public async Task<IActionResult> GetPlan()
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var plan = await _planService.GetPlanAsync(userId);
        int limit = plan.PlanType == "FREE" ? 3 : -1;
        int remaining = limit == -1 ? -1 : Math.Max(0, limit - plan.ScansThisMonth);

        var user = await _context.LocalUsers.FindAsync(userId);
        string displayName = user?.DisplayName ?? "";

        return Ok(new
        {
            plan.PlanType,
            plan.ScansThisMonth,
            Limit = limit,
            Remaining = remaining,
            DisplayName = displayName,
            IsAdmin = user?.IsAdmin ?? false
        });
    }

    [HttpGet("export")]
    public async Task<IActionResult> ExportData()
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var scans = await _context.ScanStates
            .Where(s => s.UserId == userId)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync();

        var exportData = new
        {
            UserId = userId,
            ExportDate = DateTime.UtcNow,
            TotalScans = scans.Count,
            Scans = scans
        };

        var json = System.Text.Json.JsonSerializer.Serialize(exportData, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        
        return File(bytes, "application/json", $"codesentry-export-{DateTime.UtcNow:yyyyMMdd}.json");
    }

    // --- API KEYS ---

    [HttpGet("/api/keys")]
    public async Task<IActionResult> GetKeys()
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var keys = await _context.ApiKeys
            .Where(k => k.UserId == userId)
            .Select(k => new { k.Id, k.Name, k.CreatedAt, k.LastUsed })
            .OrderByDescending(k => k.CreatedAt)
            .ToListAsync();

        return Ok(keys);
    }

    [HttpPost("/api/keys")]
    public async Task<IActionResult> CreateKey([FromBody] CreateKeyRequest request)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        // Enforce TEAM plan for API keys
        var plan = await _planService.GetPlanAsync(userId);
        if (plan.PlanType != "TEAM" && plan.PlanType != "PRO") // Allow PRO/TEAM for demo purposes
        {
            return StatusCode(403, new { error = "API keys require PRO or TEAM plan." });
        }

        var keyName = string.IsNullOrWhiteSpace(request.Name) ? "Default Key" : request.Name;
        var rawKey = "dvs_" + Guid.NewGuid().ToString("N");

        var apiKey = new ApiKey
        {
            Id = Guid.NewGuid().ToString(),
            UserId = userId,
            Name = keyName,
            KeyValue = rawKey, // In production, this should be hashed. Storing raw for demo.
            CreatedAt = DateTime.UtcNow
        };

        _context.ApiKeys.Add(apiKey);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            apiKey.Id,
            apiKey.Name,
            apiKey.CreatedAt,
            KeyValue = rawKey // Show ONLY ONCE
        });
    }

    [HttpDelete("/api/keys/{id}")]
    public async Task<IActionResult> DeleteKey(string id)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        var key = await _context.ApiKeys.FindAsync(id);
        if (key == null || key.UserId != userId) return NotFound();

        _context.ApiKeys.Remove(key);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    [HttpPatch("/api/keys/{id}")]
    public async Task<IActionResult> RenameKey(string id, [FromBody] UpdateKeyRequest request)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return Unauthorized();

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Key name is required." });

        var key = await _context.ApiKeys.FindAsync(id);
        if (key == null || key.UserId != userId) return NotFound();

        key.Name = request.Name.Trim();
        await _context.SaveChangesAsync();

        return Ok(new { key.Id, key.Name, key.CreatedAt, key.LastUsed });
    }
}

public class UpdateProfileRequest
{
    public string? DisplayName { get; set; }
}

public class CreateKeyRequest
{
    public string? Name { get; set; }
}

public class UpdateKeyRequest
{
    public string? Name { get; set; }
}
