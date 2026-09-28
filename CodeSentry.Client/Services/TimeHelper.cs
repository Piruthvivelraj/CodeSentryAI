namespace CodeSentryAI.Services;

/// <summary>
/// Helper for displaying human-readable relative timestamps throughout the UI.
/// </summary>
public static class TimeHelper
{
    /// <summary>
    /// Converts a UTC <see cref="DateTime"/> to a human-readable relative time string.
    /// Examples: "just now", "5 mins ago", "3 hours ago", "2 days ago", "May 01, 2025"
    /// </summary>
    public static string ToRelativeTime(DateTime dt)
    {
        var diff = DateTime.UtcNow - dt.ToUniversalTime();

        if (diff.TotalSeconds < 60)  return "just now";
        if (diff.TotalMinutes < 60)  return $"{(int)diff.TotalMinutes} mins ago";
        if (diff.TotalHours < 24)    return $"{(int)diff.TotalHours} hours ago";
        if (diff.TotalDays < 7)      return $"{(int)diff.TotalDays} days ago";

        return dt.ToString("MMM dd, yyyy");
    }

    /// <summary>
    /// Converts a nullable UTC <see cref="DateTime"/> to a relative time string.
    /// Returns "—" if the value is null.
    /// </summary>
    public static string ToRelativeTime(DateTime? dt) =>
        dt.HasValue ? ToRelativeTime(dt.Value) : "—";

    /// <summary>
    /// Attempts to parse a date string and return a relative time.
    /// Returns "—" if parsing fails or input is null.
    /// </summary>
    public static string ToRelativeTime(string? dateStr)
    {
        if (string.IsNullOrEmpty(dateStr)) return "—";
        return DateTime.TryParse(dateStr, out var dt) ? ToRelativeTime(dt) : "—";
    }
}
