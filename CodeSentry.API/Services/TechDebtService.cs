namespace CodeSentry.API.Services;

public class TechDebtService : ITechDebtService
{
    public decimal ConvertToDollarCost(double debtHours, decimal hourlyRate = 85m)
        => (decimal)debtHours * hourlyRate;
}
