using Postgrest.Attributes;
using Postgrest.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CodeSentry.API.Models;

[Postgrest.Attributes.Table("scan_states")]
public class ScanState : BaseModel
{
    [PrimaryKey("scan_id", false)]
    [Key]
    public string ScanId { get; set; } = string.Empty;

    [Postgrest.Attributes.Column("status")]
    public string Status { get; set; } = string.Empty; // e.g. CLONING, ANALYSIS, AI_REVIEW, REPORT

    [Postgrest.Attributes.Column("message")]
    public string Message { get; set; } = string.Empty;

    [Postgrest.Attributes.Column("progress_percent")]
    public int ProgressPercent { get; set; }

    [Postgrest.Attributes.Column("repo_size")]
    public string? RepoSize { get; set; }

    [Postgrest.Attributes.Column("estimated_time")]
    public string? EstimatedTime { get; set; }

    [Postgrest.Attributes.Column("result")]
    public ScanResult? Result { get; set; }

    [Postgrest.Attributes.Column("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The authenticated user's ID (JWT "sub" claim) who initiated this scan.
    /// Used for authorization checks on per-scan endpoints.
    /// </summary>
    [Postgrest.Attributes.Column("user_id")]
    public string? UserId { get; set; }

    [Postgrest.Attributes.Column("health_score")]
    public int HealthScore { get; set; } = 0;

    [Postgrest.Attributes.Column("repository_name")]
    public string RepositoryName { get; set; } = string.Empty;
}


public class ScanResult
{
    public string Id { get; set; } = string.Empty;
    public int Score { get; set; }
    public int TotalIssues { get; set; }
    public int CriticalIssues { get; set; }
    public int HoursSaved { get; set; }
    public string TimeAgo { get; set; } = "Just now";
    public string BorderColorClass { get; set; } = "primary";
    public string Duration { get; set; } = "-";
    
    public List<CodeIssue> Issues { get; set; } = new List<CodeIssue>();
    public List<FileSummary> FileSummaries { get; set; } = new();
}
