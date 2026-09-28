namespace CodeSentry.API.Models;

public class ScanRequest
{
    public string RepoUrl { get; set; } = string.Empty;
    public bool IsPrivate { get; set; } = false;
}
