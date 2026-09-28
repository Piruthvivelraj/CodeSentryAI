namespace CodeSentry.API.Models;

public class Repository
{
    public string Id              { get; set; } = string.Empty;
    /// <summary>Human-readable repository name (e.g. "owner/repo").</summary>
    public string Name            { get; set; } = string.Empty;
    public string LastScan        { get; set; } = string.Empty;
    public int    Coverage        { get; set; }
    public string Status          { get; set; } = string.Empty;
    public string StatusColorClass{ get; set; } = string.Empty;
    public int    CriticalCount   { get; set; }
    public int    WarningCount    { get; set; }
}
