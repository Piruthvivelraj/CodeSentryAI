using System.Text;
using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

/// <summary>
/// Detects high-entropy strings that look like secrets even without keyword matches.
/// Uses Shannon entropy to flag suspicious-looking string literals over 20 chars.
/// </summary>
public static class SecretsEntropyAnalyzer
{
    private const double EntropyThreshold = 4.5;
    private const int MinLength = 20;

    // ── Static readonly regex — compiled ONCE, reused across all file scans ──
    // Timeout prevents ReDoS on malformed input.
    private static readonly Regex EntropyPattern = new Regex(
        @"[""'][^""'\n]{20,}?[""']",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(2));

    // Suspicious base patterns that should not appear in source
    private static readonly string[] SuspiciousBases =
    {
        "password", "secret", "token", "auth", "api", "key", "private",
        "credential", "jwt", "bearer", "access", "encrypt", "crypto"
    };

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();

        foreach (var file in files)
        {
            MatchCollection matches;
            try
            {
                matches = EntropyPattern.Matches(file.Content);
            }
            catch (RegexMatchTimeoutException)
            {
                continue; // skip file on timeout — never crash the scanner
            }

            foreach (Match m in matches)
            {
                var raw = m.Value.Trim('"', '\'');
                if (string.IsNullOrWhiteSpace(raw)) continue;

                // Skip if it matches a known pattern (already caught by SecurityAnalyzer)
                var lower = raw.ToLowerInvariant();
                if (SuspiciousBases.Any(b => lower.Contains(b))) continue;

                // Calculate Shannon entropy
                var entropy = CalculateEntropy(raw);
                if (entropy >= EntropyThreshold)
                {
                    var lineNum = file.Content[..m.Index].Split('\n').Length;
                    var masked = MaskString(raw);

                    issues.Add(new CodeIssue
                    {
                        Severity = "Warning",
                        Title = "High Entropy String Detected",
                        Description = $"Possible hardcoded secret. Entropy: {entropy:F2} bits/char. Value: {masked}",
                        FilePath = file.FilePath,
                        LineNumber = lineNum,
                        Suggestion = "Investigate this string. If it is a secret, move it to environment variables or a secrets manager.",
                        EffortLevel = "Medium",
                        Category = "Security"
                    });
                }
            }
        }

        return issues;
    }

    private static double CalculateEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;

        var freq = new Dictionary<char, int>();
        foreach (var c in input)
        {
            if (!freq.ContainsKey(c)) freq[c] = 0;
            freq[c]++;
        }

        var len = input.Length;
        double entropy = 0;
        foreach (var count in freq.Values)
        {
            var p = (double)count / len;
            if (p > 0) entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string MaskString(string input)
    {
        if (input.Length <= 8) return new string('*', input.Length);
        return input[..4] + new string('*', Math.Min(input.Length - 4, 20)) +
            (input.Length > 24 ? input[^4..] : "");
    }
}
