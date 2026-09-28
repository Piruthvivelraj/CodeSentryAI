using System.Net.Http.Headers;
using System.Text.Json;

namespace CodeSentry.API.Services;

public interface IGitHubService
{
    Task<Dictionary<string, string>> GetFilesAsync(string repoUrl);
    Task<RepoMetadata?> GetRepoMetadataAsync(string repoUrl);
}

public class RepoMetadata
{
    public long Size { get; set; } // in KB
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public class GitHubService : IGitHubService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<GitHubService> _logger;

    public GitHubService(HttpClient httpClient, ILogger<GitHubService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _httpClient.BaseAddress = new Uri("https://api.github.com/");
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("CodeSentryAI", "1.0"));

        // ── FIX: Add explicit timeout to prevent hanging requests ──
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<Dictionary<string, string>> GetFilesAsync(string repoUrl)
    {
        var result = new Dictionary<string, string>();

        try
        {
            var uri = new Uri(repoUrl);
            var parts = uri.AbsolutePath.Trim('/').Split('/');
            if (parts.Length < 2) return result;

            string owner = parts[0];
            string repo  = parts[1];

            var treeResponse = await _httpClient.GetAsync($"repos/{owner}/{repo}/git/trees/HEAD?recursive=1");
            if (!treeResponse.IsSuccessStatusCode) return result;

            var treeJson = await treeResponse.Content.ReadAsStringAsync();
            var treeDoc  = JsonDocument.Parse(treeJson);

            var treeElements  = treeDoc.RootElement.GetProperty("tree").EnumerateArray();
            int filesProcessed = 0;

            foreach (var element in treeElements)
            {
                if (filesProcessed >= 10) break;

                var type = element.GetProperty("type").GetString();
                if (type == "blob")
                {
                    var path = element.GetProperty("path").GetString();

                    if (path != null && (path.EndsWith(".cs") || path.EndsWith(".js") ||
                        path.EndsWith(".ts") || path.EndsWith(".py") || path.EndsWith(".html")))
                    {
                        var contentResponse = await _httpClient.GetAsync($"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}");
                        if (contentResponse.IsSuccessStatusCode)
                        {
                            var content = await contentResponse.Content.ReadAsStringAsync();
                            result[path] = content;
                            filesProcessed++;
                        }
                    }
                }
            }
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            _logger.LogWarning("GitHub fetch timed out after 30s for {Url}", repoUrl);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("GitHub fetch error: {Error}", ex.Message);
        }

        return result;
    }

    public async Task<RepoMetadata?> GetRepoMetadataAsync(string repoUrl)
    {
        try
        {
            var uri   = new Uri(repoUrl);
            var parts = uri.AbsolutePath.Trim('/').Split('/');
            if (parts.Length < 2) return null;

            string owner = parts[0];
            string repo  = parts[1].EndsWith(".git") ? parts[1][..^4] : parts[1];

            var response = await _httpClient.GetAsync($"repos/{owner}/{repo}");
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync();
            var doc  = JsonDocument.Parse(json);

            return new RepoMetadata
            {
                Size        = doc.RootElement.GetProperty("size").GetInt64(),
                Name        = doc.RootElement.GetProperty("name").GetString() ?? "",
                Description = doc.RootElement.GetProperty("description").GetString() ?? ""
            };
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            _logger.LogWarning("GitHub metadata fetch timed out after 30s for {Url}", repoUrl);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("GitHub metadata fetch error: {Error}", ex.Message);
            return null;
        }
    }
}
