using System.Diagnostics;

namespace CodeSentry.API.Services;

public class RepoCloneResult
{
    public string LocalPath { get; set; } = string.Empty;
    public string Owner { get; set; } = string.Empty;
    public string RepoName { get; set; } = string.Empty;
}

public interface IRepoCloneService
{
    Task<RepoCloneResult> CloneAsync(string repoUrl, string scanId, CancellationToken ct = default);
    void Cleanup(string localPath);
}

public class RepoCloneService : IRepoCloneService
{
    private readonly ILogger<RepoCloneService> _logger;

    /// <summary>
    /// Allowlisted git hosting domains. Only these are accepted to prevent SSRF
    /// and path traversal attacks via malicious git URLs.
    /// </summary>
    private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "dev.azure.com"
    };

    public RepoCloneService(ILogger<RepoCloneService> logger)
    {
        _logger = logger;
    }

    public async Task<RepoCloneResult> CloneAsync(string repoUrl, string scanId, CancellationToken ct = default)
    {
        // ── SECURITY: Validate URL against allowlist BEFORE any processing ──
        ValidateGitUrl(repoUrl);

        var (normalizedUrl, owner, repoName) = ParseRepoUrl(repoUrl);

        var tempBase = Path.Combine(Path.GetTempPath(), "codesentry", scanId);
        if (Directory.Exists(tempBase))
            Directory.Delete(tempBase, true);
        Directory.CreateDirectory(tempBase);

        _logger.LogInformation("[CLONING] Connecting to GitHub...");

        try
        {
            var gitVersion = await RunProcessAsync("git", new[] { "--version" }, Path.GetTempPath(), 10, ct);
            _logger.LogInformation("[CLONING] Git found: {Version}", gitVersion.Trim());
        }
        catch
        {
            throw new InvalidOperationException("Git is not installed on server. Install git and ensure it is in PATH.");
        }

        // ── STEP 1: Shallow clone for fast-fail ──
        _logger.LogInformation("[CLONING] Cloning repository (depth=1)...");

        try
        {
            var output = await RunProcessAsync("git", new[] { "clone", "--depth=1", normalizedUrl, tempBase }, Path.GetTempPath(), 300, ct);
            _logger.LogInformation("[CLONING] Clone output: {Output}", output.Trim());
        }
        catch (TimeoutException)
        {
            Cleanup(tempBase);
            throw new InvalidOperationException("Repository clone timed out after 300 seconds.");
        }
        catch (Exception ex) when (ex.Message.Contains("128") || ex.Message.Contains("fatal"))
        {
            Cleanup(tempBase);
            throw new InvalidOperationException("Repository not found or is private. Ensure the URL is correct and the repository is publicly accessible.");
        }

        if (!Directory.Exists(Path.Combine(tempBase, ".git")))
        {
            Cleanup(tempBase);
            throw new InvalidOperationException("Repository not found or is private.");
        }

        // ── STEP 2: Unshallow to get full history for git history scanning ──
        _logger.LogInformation("[CLONING] Fetching full git history (unshallow)...");
        try
        {
            var unshallowOutput = await RunProcessAsync("git", new[] { "fetch", "--unshallow" }, tempBase, 120, ct);
            _logger.LogInformation("[CLONING] Unshallow complete: {Output}", unshallowOutput.Trim());
        }
        catch (Exception ex)
        {
            // Non-fatal — git history scanner will just have limited results
            _logger.LogWarning("[CLONING] Unshallow failed (git history scan will be limited): {Error}", ex.Message);
        }

        return new RepoCloneResult
        {
            LocalPath = tempBase,
            Owner = owner,
            RepoName = repoName
        };
    }

    public void Cleanup(string localPath)
    {
        try
        {
            if (!string.IsNullOrEmpty(localPath) && Directory.Exists(localPath))
            {
                // Git creates readonly files — need to reset attributes before delete
                foreach (var file in Directory.EnumerateFiles(localPath, "*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
                }
                Directory.Delete(localPath, true);
                _logger.LogInformation("[CLEANUP] Temp directory deleted: {Path}", localPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[CLEANUP] Failed to delete temp dir: {Error}", ex.Message);
        }
    }

    /// <summary>
    /// Validates the repository URL against the allowlist of supported git hosts.
    /// Throws <see cref="ArgumentException"/> for any disallowed host to prevent
    /// SSRF, path traversal, and internal network access via malicious URLs.
    /// </summary>
    private static void ValidateGitUrl(string repoUrl)
    {
        if (string.IsNullOrWhiteSpace(repoUrl))
            throw new ArgumentException("Repository URL cannot be empty.");

        // Strip trailing slashes and common suffixes before parsing
        var urlToParse = repoUrl.Trim().TrimEnd('/');

        // Strip /tree/branch, /blob/branch suffixes
        var treeIdx = urlToParse.IndexOf("/tree/", StringComparison.OrdinalIgnoreCase);
        if (treeIdx > 0) urlToParse = urlToParse[..treeIdx];
        var blobIdx = urlToParse.IndexOf("/blob/", StringComparison.OrdinalIgnoreCase);
        if (blobIdx > 0) urlToParse = urlToParse[..blobIdx];

        // Strip .git suffix before host check
        if (urlToParse.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            urlToParse = urlToParse[..^4];

        // Reject non-HTTP schemes (file://, ssh://, git://, etc.)
        if (!urlToParse.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !urlToParse.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Only GitHub, GitLab, Bitbucket and Azure DevOps URLs are supported. " +
                "URL must start with https://");
        }

        Uri uri;
        try
        {
            uri = new Uri(urlToParse);
        }
        catch (UriFormatException)
        {
            throw new ArgumentException($"Invalid repository URL format: {repoUrl}");
        }

        // SECURITY: Reject embedded credentials in URL (e.g., https://user:pass@github.com/...)
        if (uri.UserInfo.Length > 0 || urlToParse.Contains("@"))
        {
            throw new ArgumentException(
                "Repository URL must not contain embedded credentials. " +
                "Remove any username:password@ from the URL.");
        }

        // SECURITY: Reject private/reserved IP ranges and localhost to prevent SSRF
        // Covers full RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, ::1
        var host = uri.Host.ToLowerInvariant();
        if (host == "localhost" || host == "::1")
        {
            throw new ArgumentException(
                "Only GitHub, GitLab, Bitbucket and Azure DevOps URLs are supported.");
        }

        if (System.Net.IPAddress.TryParse(host, out var ip))
        {
            if (IsPrivateOrReservedIp(ip))
            {
                throw new ArgumentException(
                    "Only GitHub, GitLab, Bitbucket and Azure DevOps URLs are supported.");
            }
        }

        if (!AllowedHosts.Contains(host))
        {
            throw new ArgumentException(
                $"Only GitHub, GitLab, Bitbucket and Azure DevOps URLs are supported. " +
                $"Received host: {host}");
        }

        // Ensure minimum path depth (owner/repo)
        var segments = uri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2)
        {
            throw new ArgumentException(
                $"Invalid repository URL: {repoUrl}. Expected format: https://github.com/owner/repo");
        }
    }

    /// <summary>
    /// Checks if an IP address is in a private or reserved range (RFC1918 + loopback + link-local).
    /// Full coverage: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, ::1
    /// </summary>
    private static bool IsPrivateOrReservedIp(System.Net.IPAddress ip)
    {
        if (System.Net.IPAddress.IsLoopback(ip))
            return true;

        var bytes = ip.GetAddressBytes();

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 127.0.0.0/8 (loopback)
            if (bytes[0] == 127) return true;
            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 0.0.0.0
            if (bytes[0] == 0) return true;
        }

        // IPv6 loopback (::1) — already handled by IPAddress.IsLoopback
        // IPv6 link-local (fe80::/10)
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && bytes.Length == 16)
        {
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return true;
        }

        return false;
    }

    private static (string url, string owner, string repoName) ParseRepoUrl(string repoUrl)
    {
        repoUrl = repoUrl.Trim().TrimEnd('/');

        // Strip /tree/branch, /blob/branch, etc.
        var treeIdx = repoUrl.IndexOf("/tree/", StringComparison.OrdinalIgnoreCase);
        if (treeIdx > 0) repoUrl = repoUrl[..treeIdx];
        var blobIdx = repoUrl.IndexOf("/blob/", StringComparison.OrdinalIgnoreCase);
        if (blobIdx > 0) repoUrl = repoUrl[..blobIdx];

        // Strip .git suffix for parsing
        var parseUrl = repoUrl.EndsWith(".git", StringComparison.OrdinalIgnoreCase)
            ? repoUrl[..^4]
            : repoUrl;

        var uri = new Uri(parseUrl);
        var segments = uri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length < 2)
            throw new ArgumentException($"Invalid repository URL: {repoUrl}. Expected format: https://github.com/owner/repo");

        var owner = segments[0];
        var repoName = segments[1];

        // Ensure .git suffix for clone
        var cloneUrl = repoUrl.EndsWith(".git", StringComparison.OrdinalIgnoreCase)
            ? repoUrl
            : repoUrl + ".git";

        return (cloneUrl, owner, repoName);
    }

    /// <summary>
    /// Runs an external process with timeout. Internal so analyzers can reuse it.
    /// </summary>
    internal static async Task<string> RunProcessAsync(string fileName, IEnumerable<string> arguments, string workingDir, int timeoutSeconds, CancellationToken ct)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        
        foreach (var arg in arguments)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }

        process.Start();

        var outputTask = process.StandardOutput.ReadToEndAsync(ct);
        var errorTask = process.StandardError.ReadToEndAsync(ct);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            await Task.WhenAll(outputTask, errorTask, process.WaitForExitAsync(cts.Token));
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch { }
            throw new TimeoutException($"Process '{fileName}' timed out after {timeoutSeconds}s.");
        }

        var output = outputTask.Result;
        var error = errorTask.Result;

        if (process.ExitCode != 0 && !string.IsNullOrWhiteSpace(error))
        {
            throw new InvalidOperationException($"Process exited with code {process.ExitCode}: {error.Trim()}");
        }

        return string.IsNullOrWhiteSpace(output) ? error : output;
    }
}
