using System.Text;

namespace CodeSentry.API.Services;

public class ScannedFile
{
    public string FilePath { get; set; } = string.Empty;
    public string Extension { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string[] Lines { get; set; } = Array.Empty<string>();
    public int LineCount { get; set; }
    public double SizeKB { get; set; }
    public string Language { get; set; } = "Unknown";
}

public class FileWalkResult
{
    public List<ScannedFile> Files { get; set; } = new();
    public int TotalFound { get; set; }
    public int TotalSkipped { get; set; }
    public int TotalLines { get; set; }
    public int DirectoryCount { get; set; }
    public Dictionary<string, int> LanguageBreakdown { get; set; } = new();
}

public interface IFileWalker
{
    FileWalkResult Walk(string rootPath);
}

public class FileWalker : IFileWalker
{
    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", ".git", "bin", "obj", "dist", "build",
        ".vs", "packages", "vendor", "__pycache__", ".next", ".nuxt",
        "coverage", ".terraform", "migrations", ".idea", ".vscode",
        "bower_components", ".cache", ".parcel-cache", "target"
    };

    private static readonly HashSet<string> SkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
        ".exe", ".dll", ".zip", ".tar", ".gz", ".rar", ".7z",
        ".lock", ".min.js", ".min.css", ".map",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".bmp", ".webp", ".mp3", ".mp4", ".avi", ".mov",
        ".so", ".dylib", ".o", ".a", ".lib", ".pdb",
        ".class", ".jar", ".war", ".ear",
        ".pyc", ".pyo", ".DS_Store", ".suo"
    };

    private static readonly Dictionary<string, string> ExtensionToLanguage = new(StringComparer.OrdinalIgnoreCase)
    {
        { ".cs", "C#" }, { ".csx", "C#" },
        { ".js", "JavaScript" }, { ".jsx", "JavaScript" }, { ".mjs", "JavaScript" },
        { ".ts", "TypeScript" }, { ".tsx", "TypeScript" },
        { ".py", "Python" }, { ".pyw", "Python" },
        { ".java", "Java" },
        { ".go", "Go" },
        { ".rs", "Rust" },
        { ".rb", "Ruby" },
        { ".php", "PHP" },
        { ".swift", "Swift" },
        { ".kt", "Kotlin" }, { ".kts", "Kotlin" },
        { ".scala", "Scala" },
        { ".c", "C" }, { ".h", "C" },
        { ".cpp", "C++" }, { ".hpp", "C++" }, { ".cc", "C++" }, { ".cxx", "C++" },
        { ".html", "HTML" }, { ".htm", "HTML" },
        { ".css", "CSS" }, { ".scss", "SCSS" }, { ".sass", "SASS" }, { ".less", "LESS" },
        { ".json", "JSON" },
        { ".xml", "XML" }, { ".xaml", "XAML" },
        { ".yaml", "YAML" }, { ".yml", "YAML" },
        { ".md", "Markdown" },
        { ".sql", "SQL" },
        { ".sh", "Shell" }, { ".bash", "Shell" }, { ".zsh", "Shell" },
        { ".ps1", "PowerShell" }, { ".psm1", "PowerShell" },
        { ".r", "R" },
        { ".lua", "Lua" },
        { ".dart", "Dart" },
        { ".vue", "Vue" },
        { ".svelte", "Svelte" },
        { ".razor", "Razor" }, { ".cshtml", "Razor" },
        { ".tf", "Terraform" }, { ".hcl", "HCL" },
        { ".dockerfile", "Docker" },
        { ".proto", "Protocol Buffers" },
        { ".graphql", "GraphQL" }, { ".gql", "GraphQL" },
        { ".toml", "TOML" },
        { ".ini", "INI" }, { ".cfg", "Config" }, { ".conf", "Config" },
        { ".env", "Environment" },
        { ".csproj", "MSBuild" }, { ".sln", "Solution" }, { ".slnx", "Solution" },
        { ".gradle", "Gradle" },
        { ".cmake", "CMake" },
        { ".makefile", "Make" },
    };

    private const long MaxFileSizeBytes = 500 * 1024; // 500KB

    public FileWalkResult Walk(string rootPath)
    {
        var result = new FileWalkResult();
        var dirs = new HashSet<string>();

        foreach (var filePath in EnumerateFilesRecursive(rootPath))
        {
            result.TotalFound++;

            var relativePath = Path.GetRelativePath(rootPath, filePath).Replace('\\', '/');
            var ext = Path.GetExtension(filePath);

            // Check for compound extensions like .min.js
            var fileName = Path.GetFileName(filePath);
            if (fileName.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase))
            {
                result.TotalSkipped++;
                continue;
            }

            if (SkipExtensions.Contains(ext))
            {
                result.TotalSkipped++;
                continue;
            }

            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > MaxFileSizeBytes)
            {
                result.TotalSkipped++;
                continue;
            }

            // ── SECURITY: Skip file symlinks to prevent path traversal ──
            if (fileInfo.LinkTarget != null)
            {
                result.TotalSkipped++;
                continue;
            }

            // Track directory
            var dir = Path.GetDirectoryName(relativePath);
            if (!string.IsNullOrEmpty(dir)) dirs.Add(dir);

            // Read content
            string content;
            try
            {
                content = File.ReadAllText(filePath, Encoding.UTF8);
            }
            catch
            {
                try
                {
                    content = File.ReadAllText(filePath, Encoding.Latin1);
                }
                catch
                {
                    result.TotalSkipped++;
                    continue;
                }
            }

            var lines = content.Split('\n');
            var language = MapLanguage(ext, fileName);

            var scanned = new ScannedFile
            {
                FilePath = relativePath,
                Extension = ext,
                Content = content,
                Lines = lines,
                LineCount = lines.Length,
                SizeKB = Math.Round(fileInfo.Length / 1024.0, 2),
                Language = language
            };

            result.Files.Add(scanned);
            result.TotalLines += lines.Length;

            if (!result.LanguageBreakdown.ContainsKey(language))
                result.LanguageBreakdown[language] = 0;
            result.LanguageBreakdown[language]++;
        }

        result.DirectoryCount = dirs.Count;
        return result;
    }

    private IEnumerable<string> EnumerateFilesRecursive(string path)
    {
        string[] files;
        try { files = Directory.GetFiles(path); }
        catch { yield break; }

        foreach (var f in files)
            yield return f;

        string[] dirs;
        try { dirs = Directory.GetDirectories(path); }
        catch { yield break; }

        foreach (var dir in dirs)
        {
            var dirName = Path.GetFileName(dir);
            if (SkipDirs.Contains(dirName))
                continue;

            // ── SECURITY: Skip symbolic links to prevent infinite loop / directory traversal ──
            var dirInfo = new DirectoryInfo(dir);
            if (dirInfo.LinkTarget != null)
                continue;

            foreach (var f in EnumerateFilesRecursive(dir))
                yield return f;
        }
    }

    private static string MapLanguage(string ext, string fileName)
    {
        // Special file names
        var nameLower = fileName.ToLowerInvariant();
        if (nameLower == "dockerfile" || nameLower.StartsWith("dockerfile.")) return "Docker";
        if (nameLower == "makefile" || nameLower == "gnumakefile") return "Make";
        if (nameLower == "gemfile" || nameLower == "rakefile") return "Ruby";
        if (nameLower == "jenkinsfile") return "Groovy";
        if (nameLower == ".gitignore" || nameLower == ".gitattributes") return "Git Config";
        if (nameLower == ".editorconfig") return "EditorConfig";
        if (nameLower == "package.json" || nameLower == "tsconfig.json") return "JSON";
        if (nameLower == "requirements.txt" || nameLower == "pipfile") return "Python";
        if (nameLower == "go.mod" || nameLower == "go.sum") return "Go";
        if (nameLower == "cargo.toml" || nameLower == "cargo.lock") return "Rust";

        return ExtensionToLanguage.TryGetValue(ext, out var lang) ? lang : "Other";
    }
}
