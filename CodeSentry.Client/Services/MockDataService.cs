using System.Collections.Generic;
using System.Threading.Tasks;
using CodeSentryAI.Models;

namespace CodeSentryAI.Services
{
    public class MockDataService
    {
        public Task<List<RecentScan>> GetRecentScansAsync()
        {
            return Task.FromResult(new List<RecentScan>());
        }

        public Task<List<ScanLogEntry>> GetScanLogsAsync()
        {
            return Task.FromResult(new List<ScanLogEntry>());
        }

        public Task<SeverityBreakdown> GetSeverityBreakdownAsync()
        {
            return Task.FromResult(new SeverityBreakdown { Critical = 0, Warning = 0, Info = 0 });
        }

        public Task<List<AffectedFile>> GetAffectedFilesAsync()
        {
            return Task.FromResult(new List<AffectedFile>());
        }

        public Task<List<CodeIssue>> GetCodeIssuesAsync()
        {
            return Task.FromResult(new List<CodeIssue>());
        }

        public Task<List<QuickFix>> GetQuickFixesAsync()
        {
            return Task.FromResult(new List<QuickFix>());
        }
    }
}