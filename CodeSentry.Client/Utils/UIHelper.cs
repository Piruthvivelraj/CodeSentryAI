namespace CodeSentryAI.Utils;

public static class UIHelper
{
    public static string GetScoreHex(int score) => score >= 80 ? "#10B981" : score >= 50 ? "#F59E0B" : "#EF4444";
    
    public static string GetScoreLabel(int score) => score switch
    {
        >= 80 => "Nominal",
        >= 50 => "Warning",
        _ => "Critical"
    };
}
