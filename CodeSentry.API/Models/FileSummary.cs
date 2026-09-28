namespace CodeSentry.API.Models;

public class FileSummary
{
    public string FilePath { get; set; } = string.Empty;
    public int RiskScore { get; set; }
    public string RiskTier { get; set; } = "LOW";
    public int CriticalCount { get; set; }
    public int WarningCount { get; set; }
    public int InfoCount { get; set; }
}
