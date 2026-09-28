namespace CodeSentry.API;

/// <summary>
/// Named constants for all scan pipeline stage strings.
/// Use these instead of magic string literals throughout the codebase
/// to prevent typos and enable IDE-assisted refactoring.
/// </summary>
public static class ScanStages
{
    public const string Cloning   = "CLONING";
    public const string Analysis  = "ANALYSIS";
    public const string AiReview  = "AI_REVIEW";
    public const string Report    = "REPORT";
    public const string Completed = "COMPLETED";
    public const string Failed    = "FAILED";
}
