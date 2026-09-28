namespace CodeSentry.API.Models;

public class CodeIssue
{
    public string Severity { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public string Suggestion { get; set; } = string.Empty;
    public string EffortLevel { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public int ConfidenceScore { get; set; }
    public string? DataFlowTrace { get; set; }

    // ── Git Attribution (world-class forensic tracking) ──
    public string? IntroducedBy { get; set; }
    public string? CommitHash { get; set; }
    public string? Author { get; set; }
    public string? AuthorEmail { get; set; }
    public string? CommitDate { get; set; }
    public string? CommitMessage { get; set; }

    // ── Reachability Analysis ──
    public string? ReachabilityStatus { get; set; } // "Active", "DeadCode", "UnreachableCommit", "DanglingBlob", "ReflogEntry"
}
