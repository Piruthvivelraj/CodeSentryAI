using System.Security.Claims;
using CodeSentry.API.Data;
using CodeSentry.API.Models;
using CodeSentry.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CodeSentry.API.Controllers;

/// <summary>
/// Admin endpoints for system-wide management.
/// All endpoints require authentication. In a production system
/// these would require an "Admin" role claim.
/// For academic demo purposes, any authenticated user can access admin functions.
/// </summary>
[ApiController]
[Route("api/admin")]
[Authorize]
public class AdminController : ControllerBase
{
    private readonly CodeSentryDbContext _context;
    private readonly IScanService     _scanService;
    private readonly Supabase.Client? _adminClient;
    private readonly IConfiguration   _configuration;

    public AdminController(CodeSentryDbContext context, IScanService scanService, IConfiguration configuration, [FromKeyedServices("SupabaseAdmin")] Supabase.Client? adminClient = null)
    {
        _context       = context;
        _scanService   = scanService;
        _adminClient   = adminClient;
        _configuration = configuration;
    }

    // ── GET api/admin/stats ────────────────────────────────────────────────────
    /// <summary>Returns system-wide aggregate statistics.</summary>
    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        var totalUsers   = await _context.LocalUsers.CountAsync();
        var totalScans   = await _context.ScanStates.CountAsync();
        var totalApiKeys = await _context.ApiKeys.CountAsync();

        // Aggregate critical issues from JSON-serialised Result column
        var completedScans = await _context.ScanStates
            .Where(s => s.Status == "COMPLETED" && s.Result != null)
            .ToListAsync();

        int totalCritical     = completedScans.Sum(s => s.Result?.CriticalIssues ?? 0);
        int totalIssues       = completedScans.Sum(s => s.Result?.TotalIssues    ?? 0);
        int totalRepos        = completedScans.Select(s => s.RepositoryName).Distinct().Count();
        double avgHealthScore = completedScans.Count > 0
            ? completedScans.Average(s => s.Result?.Score ?? 0)
            : 0;

        return Ok(new
        {
            totalUsers,
            totalScans,
            totalApiKeys,
            totalCritical,
            totalIssues,
            totalRepos,
            avgHealthScore = (int)avgHealthScore,
            completedScans = completedScans.Count
        });
    }

    // ── GET api/admin/users ────────────────────────────────────────────────────
    /// <summary>Returns all registered users with their scan counts and plan info.</summary>
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers([FromQuery] string? search = null)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        var query = _context.LocalUsers.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            search = search.ToLower();
            query  = query.Where(u => u.Email.ToLower().Contains(search) ||
                                      u.DisplayName.ToLower().Contains(search));
        }

        var users = await query
            .OrderByDescending(u => u.LastLogin)
            .Select(u => new
            {
                u.SupabaseId,
                u.Email,
                u.DisplayName,
                u.PlanType,
                u.ScansThisMonth,
                u.LastLogin,
                u.PlanResetDate,
                u.IsActive,
                u.IsAdmin
            })
            .ToListAsync();

        // Enrich with total scan count per user
        var enriched = new List<object>();
        foreach (var u in users)
        {
            var scanCount = await _context.ScanStates
                .CountAsync(s => s.UserId == u.SupabaseId);
            enriched.Add(new
            {
                u.SupabaseId,
                u.Email,
                u.DisplayName,
                u.PlanType,
                u.ScansThisMonth,
                u.LastLogin,
                u.IsActive,
                u.IsAdmin,
                TotalScans = scanCount
            });
        }

        return Ok(enriched);
    }

    // ── PATCH api/admin/users/{id}/plan ───────────────────────────────────────
    /// <summary>Updates a user's subscription plan type.</summary>
    [HttpPatch("users/{id}/plan")]
    public async Task<IActionResult> UpdateUserPlan(string id, [FromBody] UpdatePlanRequest request)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        if (!new[] { "FREE", "PRO", "TEAM" }.Contains(request.PlanType))
            return BadRequest(new { error = "PlanType must be FREE, PRO, or TEAM." });

        var user = await _context.LocalUsers.FindAsync(id);
        if (user == null) return NotFound(new { error = "User not found." });

        user.PlanType = request.PlanType;
        await _context.SaveChangesAsync();

        return Ok(new { user.SupabaseId, user.Email, user.PlanType });
    }

    // ── GET api/admin/scans ────────────────────────────────────────────────────
    /// <summary>Returns all scans across all users (paginated).</summary>
    [HttpGet("scans")]
    public async Task<IActionResult> GetAllScans(
        [FromQuery] string? search = null,
        [FromQuery] string? status = null,
        [FromQuery] int     page   = 1,
        [FromQuery] int     size   = 20,
        [FromQuery] string? sortBy = null,
        [FromQuery] bool    sortAscending = false)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        var query = _context.ScanStates.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.ToLower();
            query = query.Where(sc => sc.ScanId.ToLower().Contains(s) ||
                                      sc.RepositoryName.ToLower().Contains(s));
        }

        if (!string.IsNullOrWhiteSpace(status))
            query = query.Where(sc => sc.Status == status.ToUpper());

        if (!string.IsNullOrWhiteSpace(sortBy))
        {
            switch (sortBy.ToLowerInvariant())
            {
                case "repositoryname":
                    query = sortAscending ? query.OrderBy(sc => sc.RepositoryName) : query.OrderByDescending(sc => sc.RepositoryName);
                    break;
                case "status":
                    query = sortAscending ? query.OrderBy(sc => sc.Status) : query.OrderByDescending(sc => sc.Status);
                    break;
                case "score":
                    query = sortAscending ? query.OrderBy(sc => sc.HealthScore) : query.OrderByDescending(sc => sc.HealthScore);
                    break;
                case "createdat":
                default:
                    query = sortAscending ? query.OrderBy(sc => sc.CreatedAt) : query.OrderByDescending(sc => sc.CreatedAt);
                    break;
            }
        }
        else
        {
            query = query.OrderByDescending(sc => sc.CreatedAt);
        }

        var total = await query.CountAsync();
        var scans = await query
            .Skip((page - 1) * size)
            .Take(size)
            .Select(sc => new
            {
                sc.ScanId,
                sc.Status,
                sc.RepositoryName,
                sc.UserId,
                sc.CreatedAt,
                sc.HealthScore,
                sc.ProgressPercent,
                Score = sc.Result != null ? sc.Result.Score : 0,
                TotalIssues = sc.Result != null ? sc.Result.TotalIssues : 0,
                CriticalIssues = sc.Result != null ? sc.Result.CriticalIssues : 0
            })
            .ToListAsync();

        return Ok(new { total, page, size, scans });
    }

    // ── DELETE api/admin/scans/{id} ────────────────────────────────────────────
    /// <summary>Permanently deletes a scan record from the database.</summary>
    [HttpDelete("scans/{id}")]
    public async Task<IActionResult> DeleteScan(string id)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        var scan = await _context.ScanStates.FindAsync(id);
        if (scan == null) return NotFound(new { error = "Scan not found." });

        _context.ScanStates.Remove(scan);
        await _context.SaveChangesAsync();

        return Ok(new { message = $"Scan {id} deleted successfully." });
    }

    // ── GET api/admin/activity ─────────────────────────────────────────────────
    /// <summary>Returns a recent activity feed (last 20 events).</summary>
    [HttpGet("activity")]
    public async Task<IActionResult> GetActivity()
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        var recentScans = await _context.ScanStates
            .OrderByDescending(s => s.CreatedAt)
            .Take(10)
            .Select(s => new
            {
                Type      = "SCAN",
                Icon      = s.Status == "COMPLETED" ? "check_circle" : s.Status == "FAILED" ? "error" : "sync",
                Color     = s.Status == "COMPLETED" ? "#10B981" : s.Status == "FAILED" ? "#EF4444" : "#3B82F6",
                Message   = $"{(string.IsNullOrEmpty(s.RepositoryName) ? s.ScanId : s.RepositoryName)} — {s.Status}",
                Timestamp = s.CreatedAt,
                Score     = s.HealthScore
            })
            .ToListAsync();

        var recentUsers = await _context.LocalUsers
            .OrderByDescending(u => u.LastLogin)
            .Take(5)
            .Select(u => new
            {
                Type      = "USER",
                Icon      = "person",
                Color     = "#8B5CF6",
                Message   = $"User logged in: {u.Email}",
                Timestamp = u.LastLogin,
                Score     = 0
            })
            .ToListAsync();

        var activity = recentScans.Cast<object>()
            .Concat(recentUsers.Cast<object>())
            .OrderByDescending(x => (DateTime)x.GetType().GetProperty("Timestamp")!.GetValue(x)!)
            .Take(20)
            .ToList();

        return Ok(activity);
    }

    // ── POST api/admin/users ───────────────────────────────────────────────────
    /// <summary>Creates a new user via Supabase Admin API and adds them to LocalUsers.</summary>
    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });
        if (_adminClient == null) return StatusCode(500, new { error = "Admin client not configured." });

        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { error = "Email and Password are required." });

        try
        {
            var serviceKey = Environment.GetEnvironmentVariable("SUPABASE_SERVICE_ROLE_KEY") ?? _configuration["Supabase:ServiceRoleKey"];
            var adminAuth = _adminClient.AdminAuth(serviceKey);

            var userAttributes = new Supabase.Gotrue.AdminUserAttributes
            {
                Email = request.Email,
                Password = request.Password,
                EmailConfirm = true
            };

            var newUser = await adminAuth.CreateUser(userAttributes);
            if (newUser == null || newUser.Id == null)
                return BadRequest(new { error = "Failed to create user in Supabase." });

            var localUser = new LocalUser
            {
                SupabaseId = newUser.Id,
                Email = request.Email,
                PlanType = request.PlanType,
                IsAdmin = request.IsAdmin,
                IsActive = true,
                LastLogin = DateTime.UtcNow,
                PlanResetDate = DateTime.UtcNow.AddMonths(1)
            };

            _context.LocalUsers.Add(localUser);
            await _context.SaveChangesAsync();

            return Ok(new { message = "User created successfully", id = newUser.Id });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }

    // ── DELETE api/admin/users/{id} ────────────────────────────────────────────
    /// <summary>Deletes a user from Supabase and cascades local deletion.</summary>
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });
        if (_adminClient == null) return StatusCode(500, new { error = "Admin client not configured." });

        try
        {
            var serviceKey = Environment.GetEnvironmentVariable("SUPABASE_SERVICE_ROLE_KEY") ?? _configuration["Supabase:ServiceRoleKey"];
            var adminAuth = _adminClient.AdminAuth(serviceKey);
            try
            {
                await adminAuth.DeleteUser(id);
            }
            catch (Supabase.Gotrue.Exceptions.GotrueException gex) when (gex.Message.Contains("404") || gex.Message.Contains("user_not_found"))
            {
                Console.WriteLine($"[AdminController] User {id} already missing in Supabase, proceeding with local DB cleanup.");
            }

            var localUser = await _context.LocalUsers.FindAsync(id);
            if (localUser != null)
            {
                _context.LocalUsers.Remove(localUser);
                var scans = await _context.ScanStates.Where(s => s.UserId == id).ToListAsync();
                _context.ScanStates.RemoveRange(scans);
                await _context.SaveChangesAsync();
            }

            return Ok(new { message = "User deleted successfully." });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AdminController] DeleteUser failed: {ex}");
            return StatusCode(500, new { error = ex.Message });
        }
    }

    // ── PATCH api/admin/users/{id}/status ──────────────────────────────────────
    /// <summary>Toggles a user's IsActive status.</summary>
    [HttpPatch("users/{id}/status")]
    public async Task<IActionResult> ToggleUserStatus(string id)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });

        var user = await _context.LocalUsers.FindAsync(id);
        if (user == null) return NotFound(new { error = "User not found." });

        user.IsActive = !user.IsActive;
        await _context.SaveChangesAsync();

        return Ok(new { user.SupabaseId, user.IsActive });
    }

    // ── POST api/admin/users/{id}/resend-email ─────────────────────────────────
    /// <summary>Resends an invite/verification email using Supabase Admin API.</summary>
    [HttpPost("users/{id}/resend-email")]
    public async Task<IActionResult> ResendVerificationEmail(string id)
    {
        if (!await IsUserAdminAsync()) return StatusCode(403, new { error = "Admin access required." });
        if (_adminClient == null) return StatusCode(500, new { error = "Admin client not configured." });

        var user = await _context.LocalUsers.FindAsync(id);
        if (user == null) return NotFound(new { error = "User not found." });

        try
        {
            var serviceKey = Environment.GetEnvironmentVariable("SUPABASE_SERVICE_ROLE_KEY") ?? _configuration["Supabase:ServiceRoleKey"];
            var adminAuth = _adminClient.AdminAuth(serviceKey);
            
            await adminAuth.InviteUserByEmail(user.Email, new Supabase.Gotrue.InviteUserByEmailOptions());
            return Ok(new { message = "Verification email sent." });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }

    private async Task<bool> IsUserAdminAsync()
    {
        var userId = User.FindFirst("sub")?.Value ?? User.FindFirst("id")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId)) return false;
        var user = await _context.LocalUsers.FindAsync(userId);
        return user?.IsAdmin ?? false;
    }
}

// ── Request Models ─────────────────────────────────────────────────────────────

public class UpdatePlanRequest
{
    public string PlanType { get; set; } = "FREE";
}

public class CreateUserRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string PlanType { get; set; } = "FREE";
    public bool IsAdmin { get; set; } = false;
}
