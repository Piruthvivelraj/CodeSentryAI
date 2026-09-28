using CodeSentry.API.Models;

namespace CodeSentry.API.Services;

public interface IPlanService
{
    Task<UserPlan> GetPlanAsync(string userId);
    Task IncrementScanCount(string userId);
    Task ResetMonthlyCountIfNeeded(string userId);
}
