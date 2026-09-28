using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

public static class StructureAnalyzer
{
    public static List<CodeIssue> Analyze(List<ScannedFile> files, string repoRoot)
    {
        var issues = new List<CodeIssue>();
        var fileNames = files.Select(f => f.FilePath.ToLowerInvariant()).ToHashSet();

        // .gitignore check
        bool hasGitignore = fileNames.Any(f => f.EndsWith(".gitignore"));
        if (!hasGitignore)
            issues.Add(S("Warning", "No .gitignore File", ".gitignore", 0,
                "Repository has no .gitignore — temporary and sensitive files may be committed.",
                "Add a .gitignore file appropriate for your project's language."));

        // Read .gitignore content for env file check
        var gitignoreContent = files.FirstOrDefault(f => f.FilePath.EndsWith(".gitignore"))?.Content ?? "";

        // .env files
        foreach (var file in files.Where(f => Path.GetFileName(f.FilePath).StartsWith(".env")))
        {
            var name = Path.GetFileName(file.FilePath);
            if (!gitignoreContent.Contains(".env"))
                issues.Add(S("Warning", "Secrets File May Be Committed", file.FilePath, 1,
                    $"{name} exists and is NOT listed in .gitignore.",
                    $"Add {name} to .gitignore immediately and rotate any exposed secrets."));

            if (name == ".env.production" || name == ".env.local")
                issues.Add(S("Warning", "Environment-Specific Secrets File", file.FilePath, 1,
                    $"{name} contains environment-specific configuration that should not be in version control.",
                    "Move to server environment variables or a secrets manager."));
        }

        // Large files > 1MB
        foreach (var file in files.Where(f => f.SizeKB > 1024))
            issues.Add(S("Warning", "Large File Committed", file.FilePath, 1,
                $"File is {file.SizeKB:F0}KB — large files bloat the repository.",
                "Use Git LFS for large files or move to external storage."));

        // Binary executables committed
        foreach (var file in files.Where(f => f.Extension is ".exe" or ".dll"))
            issues.Add(S("Warning", "Binary Executable Committed", file.FilePath, 1,
                "Compiled binaries should not be in source control.",
                "Add *.exe and *.dll to .gitignore and remove from tracking."));

        // No README
        if (!fileNames.Any(f => f.EndsWith("readme.md") || f.EndsWith("readme.txt") || f.EndsWith("readme")))
            issues.Add(S("Info", "No README Found", "README.md", 0,
                "Repository has no README documentation.",
                "Add a README.md with project description, setup instructions, and usage."));

        // No tests
        if (!files.Any(f => f.FilePath.Contains("test", StringComparison.OrdinalIgnoreCase) ||
                           f.FilePath.Contains("spec", StringComparison.OrdinalIgnoreCase) ||
                           f.FilePath.Contains("Test", StringComparison.Ordinal)))
            issues.Add(S("Info", "No Tests Detected", "", 0,
                "No test files found in the repository.",
                "Add unit tests to improve code reliability. Consider Jest, pytest, xUnit, etc."));

        // No CI/CD
        bool hasCi = files.Any(f =>
            f.FilePath.Contains(".github/workflows") ||
            f.FilePath.Contains(".gitlab-ci") ||
            f.FilePath.Contains(".travis.yml") ||
            f.FilePath.Contains("Jenkinsfile") ||
            f.FilePath.Contains("azure-pipelines") ||
            f.FilePath.Contains(".circleci"));
        if (!hasCi)
            issues.Add(S("Info", "No CI/CD Configuration", "", 0,
                "No CI/CD pipeline configuration detected.",
                "Set up GitHub Actions, GitLab CI, or similar for automated testing and deployment."));

        // No license
        if (!fileNames.Any(f => f.Contains("license") || f.Contains("licence")))
            issues.Add(S("Info", "No License File", "LICENSE", 0,
                "Repository has no license file.",
                "Add a LICENSE file to clarify usage terms (MIT, Apache 2.0, etc.)."));

        // Deep directory nesting
        foreach (var file in files)
        {
            var depth = file.FilePath.Split('/').Length;
            if (depth >= 7)
            {
                issues.Add(S("Info", "Deeply Nested Directory Structure", file.FilePath, 0,
                    $"File is nested {depth} levels deep.",
                    "Consider flattening directory structure for better navigability."));
                break; // report once
            }
        }

        return issues;
    }

    private static CodeIssue S(string sev, string title, string path, int line, string desc, string suggestion) =>
        new() { Severity = sev, Title = title, FilePath = path, LineNumber = line,
            Description = desc, Suggestion = suggestion, EffortLevel = "Easy", Category = "Structure" };
}
