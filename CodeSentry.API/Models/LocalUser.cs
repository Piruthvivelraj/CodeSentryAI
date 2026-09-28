using System.ComponentModel.DataAnnotations;

namespace CodeSentry.API.Models;

public class LocalUser
{
    [Key]
    public string SupabaseId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTime LastLogin { get; set; } = DateTime.UtcNow;
    
    // Billing and Plan Limits
    public string PlanType { get; set; } = "FREE";
    public int ScansThisMonth { get; set; } = 0;
    public DateTime? PlanResetDate { get; set; }
    public string DisplayName { get; set; } = string.Empty;

    // Role-based Access Control
    public bool IsAdmin { get; set; } = false;
    public bool IsActive { get; set; } = true;
}
