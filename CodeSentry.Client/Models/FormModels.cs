using System.ComponentModel.DataAnnotations;

namespace CodeSentryAI.Models;

// ── Login / Registration ─────────────────────────────────────────────────────

/// <summary>Blazor EditForm model for the Login page.</summary>
public class LoginFormModel
{
    [Required(ErrorMessage = "Email address is required.")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
    [StringLength(256, ErrorMessage = "Email must not exceed 256 characters.")]
    public string Email { get; set; } = "";

    [Required(ErrorMessage = "Password is required.")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters.")]
    [StringLength(128, ErrorMessage = "Password must not exceed 128 characters.")]
    public string Password { get; set; } = "";
}

/// <summary>Blazor EditForm model for the Registration / Sign-Up form.</summary>
public class RegisterFormModel : LoginFormModel
{
    [Required(ErrorMessage = "Display name is required.")]
    [StringLength(50, MinimumLength = 2, ErrorMessage = "Display name must be between 2 and 50 characters.")]
    public string DisplayName { get; set; } = "";

    [Required(ErrorMessage = "Please confirm your password.")]
    [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
    public string ConfirmPassword { get; set; } = "";
}

// ── Scanner ──────────────────────────────────────────────────────────────────

/// <summary>Blazor EditForm model for the GitHub repository scanner.</summary>
public class ScanFormModel
{
    [Required(ErrorMessage = "Repository URL is required.")]
    [Url(ErrorMessage = "Must be a valid URL.")]
    [RegularExpression(
        @"^(https?://)?github\.com/[\w\-\.]+/[\w\-\.]+(\.git)?(/.*)?$",
        ErrorMessage = "Please enter a valid GitHub repository URL (e.g. https://github.com/user/repo).")]
    [StringLength(512, ErrorMessage = "URL must not exceed 512 characters.")]
    public string RepoUrl { get; set; } = "";
}

// ── Profile / Settings ───────────────────────────────────────────────────────

/// <summary>Blazor EditForm model for updating the user display name.</summary>
public class ProfileFormModel
{
    [Required(ErrorMessage = "Display name is required.")]
    [StringLength(50, MinimumLength = 2,
        ErrorMessage = "Display name must be between 2 and 50 characters.")]
    public string DisplayName { get; set; } = "";
}

// ── API Key ──────────────────────────────────────────────────────────────────

/// <summary>Blazor EditForm model for creating or renaming an API key.</summary>
public class ApiKeyFormModel
{
    [Required(ErrorMessage = "Key name is required.")]
    [StringLength(50, MinimumLength = 2,
        ErrorMessage = "Key name must be between 2 and 50 characters.")]
    public string Name { get; set; } = "";
}
