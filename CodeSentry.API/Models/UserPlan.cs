namespace CodeSentry.API.Models;

public class UserPlan
{
    public string PlanType { get; set; } = "FREE";
    public int ScansThisMonth { get; set; } = 0;
}
