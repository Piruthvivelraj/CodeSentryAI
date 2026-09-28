using System.Collections.Generic;
using Postgrest.Attributes;
using Postgrest.Models;

namespace CodeSentryAI.Models
{
    public class RepositoryTelemetry
    {
        public string Id { get; set; } = "";
        /// <summary>Human-readable repository name (e.g. "owner/repo"). Falls back to Id if empty.</summary>
        public string Name { get; set; } = "";
        public string LastScan { get; set; } = "";
        public int Coverage { get; set; }
        public string Status { get; set; } = "";
        public string StatusColorClass { get; set; } = "";
        public int CriticalCount { get; set; }
        public int WarningCount { get; set; }
    }

    public class ScanLogEntry
    {
        public string Time { get; set; } = "";
        public string Type { get; set; } = "";
        public string Message { get; set; } = "";
        public string TextColorClass { get; set; } = "";
    }

    public class RecentScan
    {
        public string Id { get; set; } = "";
        public string TimeAgo { get; set; } = "";
        public int Score { get; set; }
        public string Status { get; set; } = "";
        public string BorderColorClass { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public string RepositoryName { get; set; } = "";
    }

    public class AffectedFile
    {
        public string Name { get; set; } = "";
        public int Percentage { get; set; }
        public string ColorClass { get; set; } = "";
    }

    public class CodeIssue
    {
        public string Severity { get; set; } = "";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public string FilePath { get; set; } = "";
        public int LineNumber { get; set; }
        public string Suggestion { get; set; } = "";
        public string EffortLevel { get; set; } = "";
        public string Category { get; set; } = "";
        public int ConfidenceScore { get; set; }
        public string? DataFlowTrace { get; set; }

        public string Location => $"{FilePath}:{LineNumber}";

        // Standardised: #F59E0B amber-500 for Warning, #10B981 emerald-500 for healthy
        public string ColorClass => Severity switch
        {
            "Critical" => "error",
            "Warning"  => "[#F59E0B]",
            _          => "primary"
        };

        public string ConfidenceLabel => ConfidenceScore >= 80 ? "HIGH"
            : ConfidenceScore >= 50 ? "MEDIUM" : "LOW";

        public string ConfidenceColor => ConfidenceScore >= 80 ? "#10B981"
            : ConfidenceScore >= 50 ? "#F59E0B" : "#6b7280";
    }

    public class QuickFix
    {
        public string Title { get; set; } = "";
        public string Difficulty { get; set; } = "";
        public string TimeEstimate { get; set; } = "";
        public string DifficultyColorClass { get; set; } = "";
    }

    public class SeverityBreakdown
    {
        public int Critical { get; set; }
        public int Warning { get; set; }
        public int Info { get; set; }
    }

    public class DashboardMetrics
    {
        public int TotalScans { get; set; }
        public int AvgScore { get; set; }
        public int TotalIssues { get; set; }
        public int CriticalIssues { get; set; }
        public int TechDebtHours { get; set; }
    }

    public class DashboardStats
    {
        public int totalScans { get; set; }
        public int avgScore { get; set; }
        public int totalIssues { get; set; }
        public int criticalIssues { get; set; }
        public int techDebtHours { get; set; }
    }

    [Table("scan_states")]
    public class ScanState : BaseModel
    {
        [PrimaryKey("scan_id", false)]
        public string ScanId { get; set; } = "";
        [Column("status")]    public string Status { get; set; } = "";
        [Column("message")]   public string Message { get; set; } = "";
        [Column("progress_percent")] public int ProgressPercent { get; set; }
        [Column("repo_size")]  public string? RepoSize { get; set; }
        [Column("estimated_time")] public string? EstimatedTime { get; set; }
        [Column("result")]    public ScanResultDto? Result { get; set; }
        [Column("created_at")] public DateTime CreatedAt { get; set; }
        [Column("health_score")] public int HealthScore { get; set; }
        [Column("repository_name")] public string RepositoryName { get; set; } = string.Empty;
    }

    public class ScanResultDto
    {
        public string Id { get; set; } = "";
        public int Score { get; set; }
        public int TotalIssues { get; set; }
        public int CriticalIssues { get; set; }
        public int HoursSaved { get; set; }
        public string TimeAgo { get; set; } = "";
        public string BorderColorClass { get; set; } = "";
        public string Duration { get; set; } = "";
        public List<CodeIssue> Issues { get; set; } = new();
        public List<FileSummary> FileSummaries { get; set; } = new();
    }

    public class ActionItem
    {
        public string RuleName { get; set; } = string.Empty;
        public int InstanceCount { get; set; }
        public List<string> AffectedFiles { get; set; } = new();
        public double EstimatedHours { get; set; }
        public double ScoreImpact { get; set; }
        public decimal DollarCost { get; set; }
        public int FixConfidence { get; set; }
    }

    public class FileSummary
    {
        public string FilePath { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public string RiskTier { get; set; } = "LOW";
        public int CriticalCount { get; set; }
        public int WarningCount { get; set; }
        public int InfoCount { get; set; }
    }
}