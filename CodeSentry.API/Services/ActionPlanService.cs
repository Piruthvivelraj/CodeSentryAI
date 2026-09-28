using CodeSentry.API.Models;

namespace CodeSentry.API.Services;

public class ActionPlanService : IActionPlanService
{
    public List<ActionItem> ComputeActionPlan(List<CodeIssue> issues)
    {
        var actionItems = new List<ActionItem>();

        // Group by Title/Rule
        var groupedIssues = issues.GroupBy(i => string.IsNullOrEmpty(i.Title) ? "Unknown Rule" : i.Title);

        foreach (var group in groupedIssues)
        {
            var ruleName = group.Key;
            var groupList = group.ToList();
            
            var instanceCount = groupList.Count;
            var affectedFiles = groupList.Select(i => i.FilePath).Distinct().ToList();
            
            var criticalCount = groupList.Count(i => i.Severity == "Critical");
            var warningCount = groupList.Count(i => i.Severity == "Warning");
            var infoCount = groupList.Count(i => i.Severity == "Info");

            // Compute EstimatedHours based on Severity and EffortLevel
            double totalEffortHours = 0;
            foreach (var issue in groupList)
            {
                double hours = 0.5; // Default for Info
                if (issue.Severity == "Warning") hours = 1.5;
                if (issue.Severity == "Critical") hours = 4.0;
                
                // Fine-tune if EffortLevel is provided
                if (!string.IsNullOrEmpty(issue.EffortLevel))
                {
                    if (issue.EffortLevel.Contains("Low", StringComparison.OrdinalIgnoreCase)) hours = 0.5;
                    else if (issue.EffortLevel.Contains("Medium", StringComparison.OrdinalIgnoreCase)) hours = 2.0;
                    else if (issue.EffortLevel.Contains("High", StringComparison.OrdinalIgnoreCase)) hours = 4.0;
                }
                
                totalEffortHours += hours;
            }

            // Calculate ScoreImpact
            double scoreImpact = (criticalCount * 10.0 + warningCount * 3.0) / Math.Log(totalEffortHours + 1.1); // +1.1 to avoid divide by zero or negative
            
            // Calculate DollarCost
            decimal dollarCost = (decimal)totalEffortHours * 85m;
            
            // Calculate FixConfidence
            int fixConfidence = 80;
            if (instanceCount < 5) fixConfidence += 10;
            if (affectedFiles.Count > 10) fixConfidence -= 15;
            
            // Just look at the most prevalent severity for confidence rules
            if (infoCount > criticalCount && infoCount > warningCount) fixConfidence += 5;
            else if (criticalCount > 0) fixConfidence -= 10;
            
            // Clamp between 40 and 97
            fixConfidence = Math.Max(40, Math.Min(97, fixConfidence));

            actionItems.Add(new ActionItem
            {
                RuleName = ruleName,
                InstanceCount = instanceCount,
                AffectedFiles = affectedFiles,
                EstimatedHours = Math.Round(totalEffortHours, 2),
                ScoreImpact = Math.Round(scoreImpact, 2),
                DollarCost = Math.Round(dollarCost, 2),
                FixConfidence = fixConfidence
            });
        }

        // Return top 5 ActionItems sorted by ScoreImpact descending
        return actionItems.OrderByDescending(a => a.ScoreImpact).Take(5).ToList();
    }
}
