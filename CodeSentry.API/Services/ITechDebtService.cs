namespace CodeSentry.API.Services;

public interface ITechDebtService
{
    decimal ConvertToDollarCost(double debtHours, decimal hourlyRate = 85m);
}
