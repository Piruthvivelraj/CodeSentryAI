using System.Threading.Channels;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services;

public class ScanProcessingWorker : BackgroundService
{
    private readonly Channel<ScanJob> _queue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ScanProcessingWorker> _logger;

    public ScanProcessingWorker(Channel<ScanJob> queue, IServiceScopeFactory scopeFactory, ILogger<ScanProcessingWorker> logger)
    {
        _queue = queue;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ScanProcessingWorker is starting.");

        try
        {
            await foreach (var job in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                _logger.LogInformation("Starting processing for scan job {ScanId}", job.ScanId);
                try
                {
                    using var scope = _scopeFactory.CreateScope();
                    var scanService = scope.ServiceProvider.GetRequiredService<IScanService>();
                    await scanService.ProcessScanAsync(job.ScanId, job.RepoUrl, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred executing scan job {ScanId}.", job.ScanId);
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("ScanProcessingWorker is stopping.");
        }
    }
}
