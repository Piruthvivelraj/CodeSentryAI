using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

public static class DependencyAnalyzer
{
    private record VulnRule(string Package, string MaxSafeVersion, string Severity, string CVE, string Description);

    /// <summary>
    /// Issue 15: Last update dates for each CVE rule set.
    /// Log a warning at startup if any rule set is older than 90 days.
    /// </summary>
    private static readonly DateTime NpmRulesLastUpdated = new(2024, 11, 15);
    private static readonly DateTime PythonRulesLastUpdated = new(2024, 11, 15);
    private static readonly DateTime DotnetRulesLastUpdated = new(2024, 11, 15);

    static DependencyAnalyzer()
    {
        // Issue 15: Check staleness of CVE databases at startup
        var staleThreshold = TimeSpan.FromDays(90);
        var now = DateTime.UtcNow;
        if (now - NpmRulesLastUpdated > staleThreshold)
            Console.Error.WriteLine($"[WARN] NPM CVE rule set is stale (last updated: {NpmRulesLastUpdated:yyyy-MM-dd}). Update DependencyAnalyzer.cs.");
        if (now - PythonRulesLastUpdated > staleThreshold)
            Console.Error.WriteLine($"[WARN] Python CVE rule set is stale (last updated: {PythonRulesLastUpdated:yyyy-MM-dd}). Update DependencyAnalyzer.cs.");
        if (now - DotnetRulesLastUpdated > staleThreshold)
            Console.Error.WriteLine($"[WARN] .NET CVE rule set is stale (last updated: {DotnetRulesLastUpdated:yyyy-MM-dd}). Update DependencyAnalyzer.cs.");
    }

    private static readonly VulnRule[] NpmRules =
    {
        new("lodash", "4.17.21", "Critical", "CVE-2021-23337", "Prototype Pollution — arbitrary code execution"),
        new("axios", "0.21.2", "Warning", "CVE-2021-3749", "SSRF vulnerability"),
        new("node-fetch", "2.6.7", "Warning", "CVE-2022-0235", "Open Redirect vulnerability"),
        new("minimist", "1.2.6", "Warning", "CVE-2021-44906", "Prototype Pollution"),
        new("tar", "6.1.9", "Critical", "CVE-2021-37713", "Path Traversal — arbitrary file write"),
        new("jquery", "3.5.0", "Warning", "CVE-2020-11022", "XSS vulnerability"),
        new("moment", "2.29.4", "Info", "CVE-2022-24785", "ReDoS vulnerability"),
        new("serialize-javascript", "3.1.0", "Critical", "CVE-2020-7660", "Remote Code Execution"),
        new("express", "4.17.3", "Warning", "", "Outdated with known security issues"),
        new("jsonwebtoken", "9.0.0", "Critical", "CVE-2022-23529", "Verification Bypass"),
        new("multer", "1.4.4", "Warning", "CVE-2022-24434", "Denial of Service"),
        new("ejs", "3.1.8", "Critical", "CVE-2022-29078", "Remote Code Execution via template injection"),
        new("vm2", "3.9.11", "Critical", "CVE-2022-36067", "Sandbox Escape — arbitrary code execution"),
        new("glob", "9.0.0", "Warning", "", "Path traversal in older versions"),
        new("socket.io-parser", "4.2.3", "Critical", "CVE-2022-21670", "Prototype Pollution"),
        new("ua-parser-js", "0.7.33", "Critical", "CVE-2022-25927", "Supply Chain Attack"),
    };

    private static readonly VulnRule[] PythonRules =
    {
        new("Django", "3.2.14", "Critical", "", "SQL injection and other known vulnerabilities"),
        new("Flask", "2.0.0", "Warning", "", "Known vulnerabilities in older versions"),
        new("Pillow", "9.0.1", "Warning", "CVE-2022-22815", "Buffer overflow vulnerability"),
        new("PyYAML", "6.0", "Critical", "CVE-2020-14343", "Arbitrary code execution via yaml.load"),
        new("requests", "2.27.0", "Warning", "", "Known security issues"),
        new("cryptography", "36.0.0", "Warning", "", "Multiple CVEs in older versions"),
        new("urllib3", "1.26.5", "Warning", "CVE-2021-33503", "Web cache poisoning"),
        new("jinja2", "3.0.3", "Warning", "CVE-2022-29969", "XSS via urlize filter"),
    };

    private static readonly VulnRule[] DotnetRules =
    {
        new("Newtonsoft.Json", "13.0.1", "Warning", "CVE-2021-26701", "Deserialization vulnerability"),
        new("System.Text.Encodings.Web", "4.5.1", "Critical", "CVE-2021-26701", "Encoding bypass vulnerability"),
        new("log4net", "2.0.13", "Critical", "CVE-2018-1285", "XXE injection vulnerability"),
    };

    private static readonly Regex WildcardVer = new(@"""\*""", RegexOptions.Compiled);
    private static readonly Regex OldVersion = new(@"(\d+)\.(\d+)\.(\d+)", RegexOptions.Compiled);

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();
        var fileNames = files.Select(f => f.FilePath.ToLowerInvariant()).ToList();

        bool hasLockfile = fileNames.Any(f =>
            f.EndsWith("package-lock.json") || f.EndsWith("yarn.lock") ||
            f.EndsWith("pnpm-lock.yaml") || f.EndsWith("packages.lock.json") ||
            f.EndsWith("requirements.lock") || f.EndsWith("poetry.lock"));

        // No lockfile
        if (fileNames.Any(f => f.EndsWith("package.json")) && !fileNames.Any(f => f.Contains("lock")))
        {
            issues.Add(Dep("Warning", "No Lockfile Found (npm)", files.First(f => f.FilePath.EndsWith("package.json")).FilePath, 1,
                "No package-lock.json or yarn.lock found — dependency versions not pinned.",
                "Run 'npm install' to generate a lockfile for deterministic builds."));
        }

        if (fileNames.Any(f => f.EndsWith("requirements.txt")) && !fileNames.Any(f => f.EndsWith("requirements.lock")))
        {
            issues.Add(Dep("Warning", "No Lockfile Found (Python)", files.First(f => f.FilePath.EndsWith("requirements.txt")).FilePath, 1,
                "No requirements.lock found — Python dependency versions not pinned.",
                "Use pip-compile or Poetry for deterministic dependency resolution."));
        }

        foreach (var file in files)
        {
            var name = Path.GetFileName(file.FilePath).ToLowerInvariant();

            if (name == "package.json") AnalyzeNpm(file, issues, hasLockfile);
            else if (name == "requirements.txt" || name == "pipfile" || name == "pyproject.toml") AnalyzePython(file, issues);
            else if (file.Extension == ".csproj") AnalyzeDotnet(file, issues);
            else if (name == "gemfile") AnalyzeGemfile(file, issues);
            else if (name == "go.mod") AnalyzeGoMod(file, issues);
            else if (name == "pom.xml") AnalyzePom(file, issues);
        }

        return issues;
    }

    private static void AnalyzeNpm(ScannedFile file, List<CodeIssue> issues, bool hasLockfile)
    {
        // Duplicate package check
        var packageLines = new Dictionary<string, List<int>>();
        for (int i = 0; i < file.Lines.Length; i++)
        {
            var line = file.Lines[i].Trim();
            var depMatch = Regex.Match(line, @"""([\w\-@/]+)""\s*:");
            if (depMatch.Success)
            {
                var pkg = depMatch.Groups[1].Value;
                if (!packageLines.ContainsKey(pkg)) packageLines[pkg] = new();
                packageLines[pkg].Add(i + 1);
            }
        }
        foreach (var dup in packageLines.Where(kv => kv.Value.Count > 1))
        {
            issues.Add(Dep("Warning", $"Duplicate Package: {dup.Key}", file.FilePath, dup.Value[0],
                $"Package '{dup.Key}' appears {dup.Value.Count} times with different versions.",
                "Deduplicate or ensure all references use the same version."));
        }

        for (int i = 0; i < file.Lines.Length; i++)
        {
            var line = file.Lines[i].Trim().Trim(',');

            if (WildcardVer.IsMatch(line))
            {
                issues.Add(Dep("Warning", "Wildcard Version Dependency", file.FilePath, i + 1,
                    "Package uses wildcard (*) version — not reproducible.",
                    "Pin to a specific version range."));
            }

            foreach (var rule in NpmRules)
            {
                if (!line.Contains($"\"{rule.Package}\"", StringComparison.OrdinalIgnoreCase)) continue;
                var ver = ExtractVersion(line);
                if (ver != null && CompareVersions(ver, rule.MaxSafeVersion) < 0)
                {
                    issues.Add(Dep(rule.Severity, $"Vulnerable: {rule.Package} {ver}", file.FilePath, i + 1,
                        $"{rule.Description}. {(rule.CVE != "" ? $"({rule.CVE})" : "")} Upgrade to >= {rule.MaxSafeVersion}.",
                        $"Run: npm install {rule.Package}@latest"));
                }
            }
        }
    }

    private static void AnalyzePython(ScannedFile file, List<CodeIssue> issues)
    {
        for (int i = 0; i < file.Lines.Length; i++)
        {
            var line = file.Lines[i].Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;

            if (line.Contains("*") || line.Contains("latest"))
            {
                issues.Add(Dep("Warning", "Unpinned/Wildcard Dependency Version", file.FilePath, i + 1,
                    "Python dependency uses wildcard or latest version.",
                    "Pin to a specific version for reproducible environments."));
            }

            foreach (var rule in PythonRules)
            {
                if (!line.StartsWith(rule.Package, StringComparison.OrdinalIgnoreCase)) continue;
                var ver = ExtractPythonVersion(line);
                if (ver != null && CompareVersions(ver, rule.MaxSafeVersion) < 0)
                {
                    issues.Add(Dep(rule.Severity, $"Vulnerable: {rule.Package} {ver}", file.FilePath, i + 1,
                        $"{rule.Description}. Upgrade to >= {rule.MaxSafeVersion}.",
                        $"Run: pip install --upgrade {rule.Package}"));
                }
            }
        }
    }

    private static void AnalyzeDotnet(ScannedFile file, List<CodeIssue> issues)
    {
        for (int i = 0; i < file.Lines.Length; i++)
        {
            var line = file.Lines[i];
            if (!line.Contains("PackageReference")) continue;

            foreach (var rule in DotnetRules)
            {
                if (!line.Contains(rule.Package, StringComparison.OrdinalIgnoreCase)) continue;
                var ver = ExtractDotnetVersion(line);
                if (ver != null && CompareVersions(ver, rule.MaxSafeVersion) < 0)
                {
                    issues.Add(Dep(rule.Severity, $"Vulnerable: {rule.Package} {ver}", file.FilePath, i + 1,
                        $"{rule.Description}. ({rule.CVE}) Upgrade to >= {rule.MaxSafeVersion}.",
                        $"Update the PackageReference Version to {rule.MaxSafeVersion} or later."));
                }
            }
        }
    }

    private static void AnalyzeGemfile(ScannedFile file, List<CodeIssue> issues)
    {
        for (int i = 0; i < file.Lines.Length; i++)
            if (file.Lines[i].Contains("gem ") && !file.Lines[i].Contains("~>") && !file.Lines[i].Contains("',"))
                issues.Add(Dep("Warning", "Unpinned Ruby Gem", file.FilePath, i + 1,
                    "Gem has no version constraint.", "Pin to a specific version range."));
    }

    private static void AnalyzeGoMod(ScannedFile file, List<CodeIssue> issues)
    {
        for (int i = 0; i < file.Lines.Length; i++)
            if (file.Lines[i].Contains("v0.0.0-") || file.Lines[i].Contains("+incompatible"))
                issues.Add(Dep("Info", "Go Pseudo-version or Incompatible Module", file.FilePath, i + 1,
                    "Module uses pseudo-version or incompatible tag.", "Update to a stable release version."));
    }

    private static void AnalyzePom(ScannedFile file, List<CodeIssue> issues)
    {
        for (int i = 0; i < file.Lines.Length; i++)
            if (file.Lines[i].Contains("<version>") && file.Lines[i].Contains("SNAPSHOT"))
                issues.Add(Dep("Warning", "SNAPSHOT Dependency in POM", file.FilePath, i + 1,
                    "SNAPSHOT versions are non-deterministic.", "Use release versions for production builds."));
    }

    private static string? ExtractVersion(string line)
    {
        var m = Regex.Match(line, @"""[~^>=<]*(\d+\.\d+[\.\d]*)""");
        return m.Success ? m.Groups[1].Value : null;
    }

    private static string? ExtractPythonVersion(string line)
    {
        var m = Regex.Match(line, @"[><=~!]+\s*(\d+\.\d+[\.\d]*)");
        if (m.Success) return m.Groups[1].Value;
        m = Regex.Match(line, @"==\s*(\d+\.\d+[\.\d]*)");
        return m.Success ? m.Groups[1].Value : null;
    }

    private static string? ExtractDotnetVersion(string line)
    {
        var m = Regex.Match(line, @"Version\s*=\s*""(\d+\.\d+[\.\d]*)""");
        return m.Success ? m.Groups[1].Value : null;
    }

    private static int CompareVersions(string a, string b)
    {
        // Issue 29: Strip pre-release suffixes (e.g., 1.0.0-beta, 2.0.0-rc1) before comparing
        static string StripPreRelease(string version)
        {
            var dashIdx = version.IndexOf('-');
            return dashIdx >= 0 ? version[..dashIdx] : version;
        }

        var pa = StripPreRelease(a).Split('.').Select(s => int.TryParse(s, out var n) ? n : 0).ToArray();
        var pb = StripPreRelease(b).Split('.').Select(s => int.TryParse(s, out var n) ? n : 0).ToArray();
        var len = Math.Max(pa.Length, pb.Length);
        for (int i = 0; i < len; i++)
        {
            var va = i < pa.Length ? pa[i] : 0;
            var vb = i < pb.Length ? pb[i] : 0;
            if (va < vb) return -1;
            if (va > vb) return 1;
        }
        return 0;
    }

    private static CodeIssue Dep(string sev, string title, string path, int line, string desc, string suggestion) =>
        new() { Severity = sev, Title = title, FilePath = path, LineNumber = line,
            Description = desc, Suggestion = suggestion, EffortLevel = "Easy", Category = "Dependency" };
}
