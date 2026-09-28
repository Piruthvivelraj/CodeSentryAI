using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CodeSentry.API.Data;
using CodeSentry.API.Models;
using Microsoft.AspNetCore.Authorization;

namespace CodeSentry.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly CodeSentryDbContext _context;

    public AuthController(CodeSentryDbContext context)
    {
        _context = context;
    }

    [Authorize]
    [HttpPost("sync")]
    public async Task<IActionResult> SyncUser()
    {
        // Extract user info from JWT claims (populated by Supabase)
        var supabaseId = User.FindFirst("sub")?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst("email")?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

        if (string.IsNullOrEmpty(supabaseId) || string.IsNullOrEmpty(email))
            return BadRequest("Invalid user claims.");

        var user = await _context.LocalUsers.FirstOrDefaultAsync(u => u.SupabaseId == supabaseId || u.Email == email);
        if (user == null)
        {
            user = new LocalUser { SupabaseId = supabaseId, Email = email };
            _context.LocalUsers.Add(user);
        }
        else
        {
            user.SupabaseId = supabaseId; // Link real Supabase UUID if it was pre-seeded
            user.LastLogin = DateTime.UtcNow;
            user.Email = email; // Update email if it changed
        }

        // Attempt to extract display_name from user_metadata in JWT claims
        var userMetadataJson = User.FindFirst("user_metadata")?.Value;
        if (!string.IsNullOrEmpty(userMetadataJson))
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(userMetadataJson);
                if (doc.RootElement.TryGetProperty("display_name", out var dnElement) && dnElement.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    user.DisplayName = dnElement.GetString() ?? user.DisplayName;
                }
            }
            catch { /* Ignore parsing errors */ }
        }

        // Dynamically elevate to admin if email matches admin@codesentry.ai
        if (email.Equals("admin@codesentry.ai", StringComparison.OrdinalIgnoreCase))
        {
            user.IsAdmin = true;
            user.DisplayName = "Admin";
        }

        await _context.SaveChangesAsync();
        return Ok(new { Message = "User synchronized successfully.", User = user });
    }
}
