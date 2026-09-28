using CodeSentry.API.Models;
using CodeSentry.API.Data;
using Microsoft.EntityFrameworkCore;

namespace CodeSentry.API.Services;

public class PlanService : IPlanService
{
    private readonly CodeSentryDbContext _dbContext;

    public PlanService(CodeSentryDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<UserPlan> GetPlanAsync(string userId)
    {
        var user = await _dbContext.LocalUsers.FirstOrDefaultAsync(u => u.SupabaseId == userId);
        if (user == null)
        {
            // If user doesn't exist yet (e.g. SyncUser hasn't completed), return default FREE plan
            return new UserPlan
            {
                PlanType = "FREE",
                ScansThisMonth = 0
            };
        }
        return new UserPlan
        {
            PlanType = user.PlanType,
            ScansThisMonth = user.ScansThisMonth
        };
    }

    public async Task IncrementScanCount(string userId)
    {
        var user = await _dbContext.LocalUsers.FirstOrDefaultAsync(u => u.SupabaseId == userId);
        if (user != null)
        {
            user.ScansThisMonth++;
            await _dbContext.SaveChangesAsync();
        }
    }

    public async Task ResetMonthlyCountIfNeeded(string userId)
    {
        var user = await _dbContext.LocalUsers.FirstOrDefaultAsync(u => u.SupabaseId == userId);
        if (user != null)
        {
            if (!user.PlanResetDate.HasValue || user.PlanResetDate.Value <= DateTime.UtcNow)
            {
                user.ScansThisMonth = 0;
                user.PlanResetDate = DateTime.UtcNow.AddMonths(1);
                await _dbContext.SaveChangesAsync();
            }
        }
    }
}
