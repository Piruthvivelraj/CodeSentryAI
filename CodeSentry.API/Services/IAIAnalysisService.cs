using System.Text.Json.Serialization;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services;

public class AnalysisResult
{
    [JsonPropertyName("healthScore")]
    public int HealthScore { get; set; }

    [JsonPropertyName("issues")]
    public List<CodeIssue> Issues { get; set; } = new();

    [JsonPropertyName("securityVulnerabilities")]
    public List<string> SecurityVulnerabilities { get; set; } = new();

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = string.Empty;

    [JsonPropertyName("fileSummaries")]
    public List<FileSummary> FileSummaries { get; set; } = new();
}

public interface IAIAnalysisService
{
    Task<AnalysisResult> AnalyzeRepositoryAsync(List<string> files, string repoUrl);
    Task<AnalysisResult> AnalyzeLocalAsync(FileWalkResult walkResult, string repoRoot, IProgress<string>? progress = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Thin wrapper — delegates to StaticAnalysisEngine for local analysis.
/// The old Gemini API path is removed. Zero external API calls.
/// </summary>
public class AIAnalysisService : IAIAnalysisService
{
    private readonly IStaticAnalysisEngine _engine;

    public AIAnalysisService(IStaticAnalysisEngine engine)
    {
        _engine = engine;
    }

    /// <summary>Legacy signature kept for backward compat — returns mock if called directly.</summary>
    public Task<AnalysisResult> AnalyzeRepositoryAsync(List<string> files, string repoUrl)
    {
        return Task.FromResult(new AnalysisResult
        {
            HealthScore = 50,
            Summary = "Legacy API path — use local analysis via ScanService.",
            Issues = new List<CodeIssue>()
        });
    }

    /// <summary>Primary analysis path — uses the local static analysis engine (now async).</summary>
    public async Task<AnalysisResult> AnalyzeLocalAsync(FileWalkResult walkResult, string repoRoot, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        return await _engine.AnalyzeAsync(walkResult, repoRoot, progress, cancellationToken);
    }
}
