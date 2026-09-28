namespace CodeSentry.API.Models;

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
