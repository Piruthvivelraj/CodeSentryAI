using CodeSentry.API.Services;
using QuestPDF.Infrastructure;
using CodeSentry.API.Data;
using CodeSentry.API.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Threading.Channels;
using Supabase;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

QuestPDF.Settings.License = LicenseType.Community;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ── SECURITY: Read Supabase credentials from environment variables first,
// fall back to appsettings.json for local development ONLY.
// In production, set SUPABASE_URL, SUPABASE_KEY, SUPABASE_JWT_SECRET env vars.
// Never commit real credentials to source control.
var supabaseUrl =
    Environment.GetEnvironmentVariable("SUPABASE_URL")
    ?? builder.Configuration["Supabase:Url"]
    ?? "";

var supabaseKey =
    Environment.GetEnvironmentVariable("SUPABASE_KEY")
    ?? builder.Configuration["Supabase:Key"]
    ?? "";

var supabaseJwtSecret =
    Environment.GetEnvironmentVariable("SUPABASE_JWT_SECRET")
    ?? builder.Configuration["Supabase:JwtSecret"]
    ?? "";

if (string.IsNullOrWhiteSpace(supabaseUrl))
{
    Console.WriteLine("[WARN] SUPABASE_URL is not set. Supabase sync will be unavailable.");
}

// Configure Supabase Client as Singleton — safe to share, manages its own connection pool
var supabaseOptions = new SupabaseOptions { AutoRefreshToken = true, AutoConnectRealtime = true };

Supabase.Client? supabaseClient = null;
if (!string.IsNullOrWhiteSpace(supabaseUrl) && !string.IsNullOrWhiteSpace(supabaseKey))
{
    try
    {
        supabaseClient = new Supabase.Client(supabaseUrl, supabaseKey, supabaseOptions);
        await supabaseClient.InitializeAsync();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[WARN] Supabase init failed — running in local-only mode: {ex.Message}");
        supabaseClient = new Supabase.Client(supabaseUrl, supabaseKey, supabaseOptions);
    }
}
else
{
    // Create a dummy client that will gracefully fail — all DB ops fall back to SQLite
    supabaseClient = new Supabase.Client("https://placeholder.supabase.co", "placeholder", supabaseOptions);
}

var supabaseServiceRoleKey =
    Environment.GetEnvironmentVariable("SUPABASE_SERVICE_ROLE_KEY")
    ?? builder.Configuration["Supabase:ServiceRoleKey"]
    ?? "";

Supabase.Client? supabaseAdminClient = null;
if (!string.IsNullOrWhiteSpace(supabaseUrl) && !string.IsNullOrWhiteSpace(supabaseServiceRoleKey))
{
    try
    {
        supabaseAdminClient = new Supabase.Client(supabaseUrl, supabaseServiceRoleKey, supabaseOptions);
        await supabaseAdminClient.InitializeAsync();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[WARN] Supabase Admin init failed: {ex.Message}");
    }
}

builder.Services.AddSingleton(supabaseClient);
if (supabaseAdminClient != null)
{
    builder.Services.AddKeyedSingleton("SupabaseAdmin", supabaseAdminClient);
}

// Configure JWT Bearer Auth using Supabase's JWKS endpoint.
// Supabase uses ES256 (P-256 elliptic curve) — we must manually build the ECDsa key
// from the 'x' and 'y' coordinates in the JWKS response.
if (!string.IsNullOrWhiteSpace(supabaseUrl))
{
    var jwksUri = $"{supabaseUrl}/auth/v1/.well-known/jwks.json";
    Console.WriteLine($"[AUTH] Fetching signing keys from: {jwksUri}");

    // Fetch and parse the JWKS at startup to build the EC signing key
    List<SecurityKey> signingKeys = new();
    try
    {
        using var http = new HttpClient();
        var jwksJson = await http.GetStringAsync(jwksUri);
        var jwks = System.Text.Json.JsonDocument.Parse(jwksJson);
        foreach (var key in jwks.RootElement.GetProperty("keys").EnumerateArray())
        {
            var kty = key.GetProperty("kty").GetString();
            var kid = key.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;

            if (kty == "EC")
            {
                var crv = key.GetProperty("crv").GetString();
                var x = key.GetProperty("x").GetString()!;
                var y = key.GetProperty("y").GetString()!;

                var ecParams = new System.Security.Cryptography.ECParameters
                {
                    Curve = crv == "P-256"
                        ? System.Security.Cryptography.ECCurve.NamedCurves.nistP256
                        : crv == "P-384"
                            ? System.Security.Cryptography.ECCurve.NamedCurves.nistP384
                            : System.Security.Cryptography.ECCurve.NamedCurves.nistP521,
                    Q = new System.Security.Cryptography.ECPoint
                    {
                        X = Base64UrlDecode(x),
                        Y = Base64UrlDecode(y)
                    }
                };

                var ecdsa = System.Security.Cryptography.ECDsa.Create(ecParams);
                var ecKey = new ECDsaSecurityKey(ecdsa) { KeyId = kid };
                signingKeys.Add(ecKey);
                Console.WriteLine($"[AUTH] Loaded EC key kid={kid}");
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[AUTH WARN] Failed to fetch JWKS: {ex.Message}. Auth will not work.");
    }

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.IncludeErrorDetails = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateIssuer = true,
                ValidIssuer = $"{supabaseUrl}/auth/v1",
                ValidateAudience = true,
                ValidAudience = "authenticated",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    Console.WriteLine($"[AUTH FAIL] {context.Exception.GetType().Name}: {context.Exception.Message}");
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    var sub = context.Principal?.FindFirst("sub")?.Value ?? "unknown";
                    Console.WriteLine($"[AUTH OK] Token validated for sub={sub}");
                    return Task.CompletedTask;
                },
                OnChallenge = context =>
                {
                    var hasToken = !string.IsNullOrEmpty(context.Request.Headers["Authorization"].ToString());
                    Console.WriteLine($"[AUTH CHALLENGE] HasToken={hasToken}, Error={context.Error}, Description={context.ErrorDescription}");
                    return Task.CompletedTask;
                }
            };
        });
}
else
{
    builder.Services.AddAuthentication();
}

// Helper: Base64Url decode (no padding)
static byte[] Base64UrlDecode(string s)
{
    s = s.Replace('-', '+').Replace('_', '/');
    switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
    return Convert.FromBase64String(s);
}



builder.Services.AddMemoryCache();

// ── SECURITY: Explicit CORS origins — no wildcard host matching ──
// Add your production domain to this list before deploying.
builder.Services.AddCors(options =>
{
    options.AddPolicy("BlazorPolicy", policy =>
    {
        policy.WithOrigins(
                "http://localhost:5237",
                "http://localhost:5000",
                "http://localhost:3000",
                "http://localhost:7001",
                "https://localhost:7001",
                "https://codesentry.ai",
                "https://www.codesentry.ai"
              )
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Register services — static analysis engine (zero external API calls)
builder.Services.AddDbContext<CodeSentryDbContext>(options =>
    options.UseSqlite("Data Source=scans.db"));

builder.Services.AddHttpClient<IGitHubService, GitHubService>()
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromSeconds(120) });
builder.Services.AddSingleton<IRepoCloneService, RepoCloneService>();
builder.Services.AddSingleton<IFileWalker, FileWalker>();
builder.Services.AddSingleton<IStaticAnalysisEngine, StaticAnalysisEngine>();
builder.Services.AddSingleton<IAIAnalysisService, AIAnalysisService>();

builder.Services.AddSingleton(Channel.CreateBounded<ScanJob>(new BoundedChannelOptions(100) { FullMode = BoundedChannelFullMode.Wait }));
builder.Services.AddSingleton<IScanService, ScanService>(); // Singleton: uses ConcurrentDictionary + Supabase (both thread-safe)
builder.Services.AddHostedService<ScanProcessingWorker>();
builder.Services.AddSingleton<IPdfReportService, PdfReportService>();

// ── V2.0 SERVICES ──
builder.Services.AddScoped<IPlanService, PlanService>();
builder.Services.AddSingleton<IActionPlanService, ActionPlanService>();
builder.Services.AddSingleton<ITechDebtService, TechDebtService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "CodeSentry API V1"));
}

// Apply EF Core migrations on startup — creates/upgrades the SQLite schema automatically.
// Uses Database.Migrate() instead of EnsureCreated() so migration history is tracked.
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<CodeSentryDbContext>();
    dbContext.Database.Migrate();

    // ── DEMO/VIVA DATA SEEDER ──
    // If the database is completely empty, insert some realistic demo data so the dashboards look populated.
    if (!dbContext.LocalUsers.Any())
    {
        var demoUserId = Guid.NewGuid().ToString();
        dbContext.LocalUsers.Add(new CodeSentry.API.Models.LocalUser
        {
            SupabaseId = demoUserId,
            Email = "admin@codesentry.ai",
            DisplayName = "Admin",
            PlanType = "PRO",
            ScansThisMonth = 3,
            LastLogin = DateTime.UtcNow,
            PlanResetDate = DateTime.UtcNow.AddDays(25),
            IsAdmin = true
        });

        if (!dbContext.ScanStates.Any())
        {
            dbContext.ScanStates.AddRange(
                new CodeSentry.API.Models.ScanState
                {
                    ScanId = Guid.NewGuid().ToString(),
                    UserId = demoUserId,
                    RepositoryName = "microsoft/vscode",
                    Status = "COMPLETED",
                    CreatedAt = DateTime.UtcNow.AddDays(-2),
                    HealthScore = 92,
                    ProgressPercent = 100,
                    Message = "Scan finished successfully."
                },
                new CodeSentry.API.Models.ScanState
                {
                    ScanId = Guid.NewGuid().ToString(),
                    UserId = demoUserId,
                    RepositoryName = "facebook/react",
                    Status = "COMPLETED",
                    CreatedAt = DateTime.UtcNow.AddHours(-12),
                    HealthScore = 78,
                    ProgressPercent = 100,
                    Message = "Scan finished successfully."
                },
                new CodeSentry.API.Models.ScanState
                {
                    ScanId = Guid.NewGuid().ToString(),
                    UserId = demoUserId,
                    RepositoryName = "vuejs/vue",
                    Status = "COMPLETED",
                    CreatedAt = DateTime.UtcNow.AddHours(-1),
                    HealthScore = 85,
                    ProgressPercent = 100,
                    Message = "Scan finished successfully."
                }
            );
        }
        
        dbContext.SaveChanges();
        Console.WriteLine("[SEED] Demo data successfully inserted for Viva presentation.");
    }
}

app.UseCors("BlazorPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
