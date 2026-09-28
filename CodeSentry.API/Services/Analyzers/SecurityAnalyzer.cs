using System.Text.RegularExpressions;
using CodeSentry.API.Models;

namespace CodeSentry.API.Services.Analyzers;

public static class SecurityAnalyzer
{
    private static readonly (string Pattern, string Title, string Severity, string Desc, string Suggestion)[] Rules =
    {
        // ── CRITICAL: Hardcoded Credentials ──
        (@"(password|passwd|pwd)\s*[=:]\s*[""'][^""'\s]{3,}[""']", "Hardcoded Password", "Critical",
            "Password is hardcoded in source code.", "Move to environment variables or a secrets manager like Azure Key Vault."),
        (@"(secret|secret_key|secretkey)\s*[=:]\s*[""'][^""'\s]{3,}[""']", "Hardcoded Secret Key", "Critical",
            "Secret key is hardcoded in source code.", "Use environment variables or a vault service."),
        (@"(api_key|apikey|api_secret)\s*[=:]\s*[""'][^""'\s]{3,}[""']", "Hardcoded API Key", "Critical",
            "API key is hardcoded in source code.", "Store API keys in environment variables, never in code."),
        (@"(access_token|auth_token|bearer)\s*[=:]\s*[""'][^""'\s]{3,}[""']", "Hardcoded Access Token", "Critical",
            "Authentication token is hardcoded.", "Rotate this token immediately and move to secure storage."),
        (@"(private_key|privatekey)\s*[=:]\s*[""'][^""'\s]{3,}[""']", "Hardcoded Private Key", "Critical",
            "Private key value is embedded in code.", "Store private keys in secure key management systems."),
        (@"AKIA[0-9A-Z]{16}", "AWS Access Key Exposed", "Critical",
            "AWS access key ID found in source code.", "Rotate this key immediately via AWS IAM console and use IAM roles instead."),
        (@"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "Private Key File Committed", "Critical",
            "A private key is committed to the repository.", "Remove the key, rotate it, and add *.pem to .gitignore."),
        (@"mongodb(\+srv)?://[^:]+:[^@]+@", "MongoDB Connection String with Credentials", "Critical",
            "Database connection string contains embedded credentials.", "Use environment variables for connection strings."),
        (@"postgres://[^:]+:[^@]+@", "PostgreSQL Connection String with Credentials", "Critical",
            "PostgreSQL connection string contains embedded credentials.", "Move connection strings to environment configuration."),
        (@"mysql://[^:]+:[^@]+@", "MySQL Connection String with Credentials", "Critical",
            "MySQL connection string contains embedded credentials.", "Use secure configuration for database credentials."),
        (@"redis://[^:]+:[^@]+@", "Redis Connection String with Credentials", "Critical",
            "Redis connection string contains embedded credentials.", "Move to environment variables."),
        (@"Authorization:\s*Bearer\s+[A-Za-z0-9_\-]+", "Hardcoded Bearer Token", "Critical",
            "Authorization Bearer token is hardcoded in source code.", "Use OAuth tokens from environment variables."),
        (@"\.pfx|\.p12", "Certificate File with Hardcoded Password", "Critical",
            "PFX/P12 certificate reference found — ensure password is not hardcoded.", "Load certificate from secure vault."),
        (@"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live API Key Exposed", "Critical",
            "Stripe live API key found — this can lead to financial fraud.", "Rotate immediately and use server-side only storage."),
        (@"pk_live_[a-zA-Z0-9]{24,}", "Stripe Live Public Key Exposed", "Critical",
            "Stripe live public key found.", "This is less sensitive but still should not be committed."),
        (@"AC[a-z0-9]{32}", "Twilio API Key Exposed", "Critical",
            "Twilio account credential exposed.", "Rotate immediately via Twilio console."),
        (@"firebase.*apiKey\s*[=:]\s*[""'][^""'\s]+[""']", "Firebase Config with Hardcoded API Key", "Critical",
            "Firebase configuration with embedded API key found.", "Use environment variables for Firebase config."),
        (@"ssh-rsa\s+AAAA[^\s]+", "SSH Private Key Block Committed", "Critical",
            "SSH private key is committed to the repository.", "Remove immediately, rotate keys, add to .gitignore."),
        (@"-----BEGIN PGP PRIVATE KEY BLOCK-----", "GPG Private Key Committed", "Critical",
            "GPG private key is committed to the repository.", "Remove immediately, rotate keys."),
        (@"\b10\.(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){2}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b", "Hardcoded IP Address in Config", "Critical",
            "Hardcoded IP address detected — indicates production infrastructure exposure.", "Use hostnames or environment-specific config."),
        (@"aws_access_key|aws_secret_key", "AWS Secret Key Pattern", "Critical",
            "AWS secret access key pattern detected.", "Use IAM roles instead of access keys."),
        (@"Base64\.Decode|Convert\.FromBase64|string\.fromcharcode", "Base64 Decoded Strings", "Info",
            "Base64 decoding detected — may be used to obscure hardcoded secrets.", "Investigate decoded content and remove secrets."),

        // ── CRITICAL: Injection ──
        (@"""SELECT\s.+\+\s*.+", "SQL Injection via String Concatenation", "Critical",
            "SQL query built by concatenating user input.", "Use parameterized queries or an ORM like Entity Framework."),
        (@"""INSERT INTO.+\+", "SQL Injection in INSERT Statement", "Critical",
            "INSERT query built with string concatenation.", "Use parameterized queries to prevent SQL injection."),
        (@"string\.Format\(""(SELECT|INSERT|UPDATE|DELETE)", "SQL Injection via String.Format", "Critical",
            "SQL query built using String.Format with potential user input.", "Use parameterized queries instead of string formatting."),
        (@"Process\.Start\(.+Request\.", "Command Injection Risk", "Critical",
            "User input passed directly to Process.Start.", "Validate and sanitize all inputs before passing to system commands."),
        (@"exec\(\s*[^""']", "Command Injection (exec)", "Critical",
            "Unparameterized exec() call detected.", "Use parameterized commands or a safe execution wrapper."),
        (@"system\(\s*[^""']", "Command Injection (system)", "Critical",
            "Unparameterized system() call detected.", "Avoid system() — use language-specific safe APIs."),
        (@"os\.system\(|subprocess\.(call|run|check_output)\(", "OS Command Injection", "Critical",
            "OS command execution with string concatenation detected.", "Use parameterized subprocess calls."),
        (@"Runtime\.exec\(", "Java Runtime.exec() Usage", "Critical",
            "Runtime.exec() can be dangerous with user input.", "Use ProcessBuilder with validated arguments only."),

        // ── CRITICAL: Dangerous Deserialization ──
        (@"BinaryFormatter\.(Serialize|Deserialize)", "BinaryFormatter Usage", "Critical",
            "BinaryFormatter is inherently insecure and vulnerable to RCE.", "Use System.Text.Json or protobuf instead."),
        (@"JsonConvert\.DeserializeObject.*TypeNameHandling", "Insecure JSON Deserialization", "Critical",
            "TypeNameHandling in Newtonsoft.Json enables type injection attacks.", "Remove TypeNameHandling or use a SerializationBinder."),
        (@"pickle\.loads\(", "Insecure Pickle Deserialization", "Critical",
            "pickle.loads() can execute arbitrary code.", "Use json.loads() or a safe serialization format."),
        (@"yaml\.load\([^,)]*\)", "Unsafe YAML Loading", "Critical",
            "yaml.load() without Loader parameter can execute arbitrary code.", "Use yaml.safe_load() instead."),
        (@"ObjectInputStream", "Java Object Deserialization", "Critical",
            "Raw Java object deserialization is unsafe.", "Use JSON or encrypted serialization."),

        // ── WARNING: Weak Cryptography ──
        (@"new MD5CryptoServiceProvider", "Weak Hash: MD5", "Warning",
            "MD5 is cryptographically broken.", "Use SHA-256 or SHA-3 for hashing."),
        (@"MD5\.Create\(\)", "Weak Hash: MD5", "Warning",
            "MD5 is cryptographically broken and unsuitable for security.", "Use SHA256.Create() instead."),
        (@"SHA1\.Create\(\)", "Weak Hash: SHA1", "Warning",
            "SHA-1 is deprecated for security use.", "Migrate to SHA-256 or SHA-3."),
        (@"new DESCryptoServiceProvider", "Weak Cipher: DES", "Warning",
            "DES uses 56-bit keys, trivially brute-forced.", "Use AES with 256-bit keys."),
        (@"new RC2CryptoServiceProvider", "Weak Cipher: RC2", "Warning",
            "RC2 is considered insecure.", "Use AES-256-GCM for symmetric encryption."),
        (@"Math\.random\(\).*(token|secret|key|password)", "Insecure Random for Security", "Warning",
            "Math.random() is not cryptographically secure.", "Use crypto.randomBytes() or window.crypto.getRandomValues()."),
        (@"Random\(\)\.Next.*(token|auth|secret)", "Insecure Random for Auth", "Warning",
            "System.Random is predictable and unsafe for security tokens.", "Use RandomNumberGenerator.GetBytes() instead."),

        // ── WARNING: Auth/AuthZ ──
        (@"AllowAnyOrigin\(\)", "CORS Wildcard Origin", "Warning",
            "CORS configured to allow any origin.", "Restrict to specific trusted origins."),
        (@"JWT.*none.*algorithm", "JWT None Algorithm Allowed", "Warning",
            "JWT library configured to allow 'none' algorithm — allows token forgery.", "Disable 'none' algorithm explicitly."),
        (@"Cookie.*HttpOnly.*false|Cookie.*Secure.*false", "Insecure Cookie Configuration", "Warning",
            "Cookie missing HttpOnly or Secure flag.", "Set HttpOnly=true and Secure=true for production cookies."),
        (@"app\.UseHsts\(", "Missing HTTPS Redirect", "Warning",
            "HTTPS enforcement may not be configured.", "Enable HTTPS redirect in production."),
        (@"Exception.*stack ?trace|\.StackTrace", "Stack Trace Exposure", "Warning",
            "Stack traces may be exposed to users.", "Log errors server-side, return generic messages to clients."),
        (@"Response\.Redirect.*\+.*Request", "Open Redirect Vulnerability", "Warning",
            "Open redirect — user input used in redirect target.", "Validate redirect URLs against an allowlist."),
        (@"(x|X)-Frame-Options.*DENY", "X-Frame-Options Header Missing", "Warning",
            "Missing X-Frame-Options header — clickjacking risk.", "Add X-Frame-Options: DENY or use CSP frame-ancestors."),

        // ── INFO: ReDoS ──
        (@"\(\?[<!=][^)]*([\+\*])[^)]*\)", "ReDoS Vulnerable Nested Quantifier", "Info",
            "Nested quantifiers detected — potential ReDoS vulnerability.", "Refactor regex to eliminate exponential complexity."),

        // ── WARNING: Insecure Config ──
        (@"SSL\s*=\s*false", "SSL Disabled", "Warning",
            "SSL/TLS is explicitly disabled.", "Enable SSL for all connections."),
        (@"verify\s*=\s*False", "SSL Verification Disabled (Python)", "Warning",
            "SSL certificate verification is disabled.", "Enable certificate verification for secure connections."),
        (@"TrustServerCertificate\s*=\s*true", "TrustServerCertificate Enabled", "Warning",
            "Server certificate validation is bypassed.", "Use proper certificate validation in production."),
        (@"validate_integrity\s*=\s*false", "JWT Signature Validation Disabled", "Warning",
            "JWT signature validation is disabled — tokens can be forged.", "Always validate JWT signatures."),

        // ── INFO: Debug / TODO ──
        (@"app\.UseDeveloperExceptionPage\(\)", "Developer Exception Page Enabled", "Info",
            "Developer exception page may leak sensitive information.", "Ensure this is only enabled in Development environment."),
        (@"DEBUG\s*=\s*True", "Debug Mode Enabled", "Info",
            "Debug mode is enabled, may expose sensitive data.", "Set DEBUG=False in production."),
        (@"""debug""\s*:\s*true", "Debug Flag in Config", "Info",
            "Debug flag set to true in configuration.", "Disable debug mode for production deployments."),
        (@"//\s*TODO[:\s]", "TODO Comment", "Info",
            "Unresolved TODO marker indicates incomplete work.", "Address or create a tracked issue for this TODO."),
        (@"//\s*FIXME", "FIXME Comment", "Info",
            "FIXME marker indicates a known bug.", "Fix the issue or file a bug ticket."),
        (@"//\s*HACK", "HACK Comment", "Info",
            "HACK marker indicates a workaround.", "Refactor to a proper solution."),
        (@"//\s*XXX", "XXX Comment", "Info",
            "XXX marker indicates problematic code.", "Review and refactor this code section."),
        (@"password.*\.log\(|console\.log.*password|log.*token", "Sensitive Data in Logs", "Info",
            "Potentially sensitive data being logged.", "Remove or mask credentials and tokens in log statements."),
        (@"Content-Security-Policy", "Content-Security-Policy Header Missing", "Info",
            "CSP header not explicitly set.", "Add CSP header to mitigate XSS attacks."),
        (@"Strict-Transport-Security", "HSTS Header Missing", "Info",
            "HSTS header not set — browser won't enforce HTTPS.", "Add Strict-Transport-Security header."),
    };

    private static readonly Lazy<(Regex Rx, string Title, string Severity, string Desc, string Suggestion)[]> Compiled = new(() =>
    {
        var result = new List<(Regex Rx, string Title, string Severity, string Desc, string Suggestion)>();
        foreach (var r in Rules)
        {
            try
            {
                result.Add((
                    new Regex(r.Pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(500)),
                    r.Title, r.Severity, r.Desc, r.Suggestion
                ));
            }
            catch (ArgumentException)
            {
                // Invalid regex pattern — skip silently, outer engine logs by analyzer name
            }
        }
        return result.ToArray();
    });

    public static List<CodeIssue> Analyze(List<ScannedFile> files)
    {
        var issues = new List<CodeIssue>();
        var rules = Compiled.Value;

        foreach (var file in files)
        {
            for (int i = 0; i < file.Lines.Length; i++)
            {
                var line = file.Lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                foreach (var rule in rules)
                {
                    try
                    {
                        if (rule.Rx.IsMatch(line))
                        {
                            issues.Add(new CodeIssue
                            {
                                Severity    = rule.Severity,
                                Title       = rule.Title,
                                Description = rule.Desc,
                                FilePath    = file.FilePath,
                                LineNumber  = i + 1,
                                Suggestion  = rule.Suggestion,
                                EffortLevel = rule.Severity == "Critical" ? "Medium" : "Easy",
                                Category    = "Security"
                            });
                        }
                    }
                    catch (RegexMatchTimeoutException) { }
                }
            }
        }
        return issues;
    }
}
