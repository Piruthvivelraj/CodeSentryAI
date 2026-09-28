using CodeSentry.API.Models;

namespace CodeSentry.API.Services;

public interface IActionPlanService
{
    List<ActionItem> ComputeActionPlan(List<CodeIssue> issues);
}
