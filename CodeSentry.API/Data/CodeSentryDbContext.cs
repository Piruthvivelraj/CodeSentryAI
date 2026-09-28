using CodeSentry.API.Models;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace CodeSentry.API.Data;

public class CodeSentryDbContext : DbContext
{
    public CodeSentryDbContext(DbContextOptions<CodeSentryDbContext> options) : base(options) { }

    public DbSet<ScanState>  ScanStates  { get; set; }
    public DbSet<LocalUser>  LocalUsers  { get; set; }
    public DbSet<ApiKey>     ApiKeys     { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // ── ScanState ──────────────────────────────────────────────────
        modelBuilder.Entity<ScanState>(entity =>
        {
            entity.HasKey(e => e.ScanId);
            entity.ToTable("ScanStates");

            // Ignore Postgrest.Models.BaseModel properties that EF Core must not map
            entity.Ignore("ClientOptions");
            entity.Ignore("BaseUrl");
            entity.Ignore("RequestClientOptions");

            // Explicit column mappings for demo/viva clarity
            entity.Property(e => e.ScanId)         .HasColumnName("ScanId")          .IsRequired().HasMaxLength(128);
            entity.Property(e => e.Status)          .HasColumnName("Status")           .IsRequired().HasMaxLength(32);
            entity.Property(e => e.Message)         .HasColumnName("Message")          .HasMaxLength(1024);
            entity.Property(e => e.ProgressPercent) .HasColumnName("ProgressPercent");
            entity.Property(e => e.RepoSize)        .HasColumnName("RepoSize")         .HasMaxLength(32);
            entity.Property(e => e.EstimatedTime)   .HasColumnName("EstimatedTime")    .HasMaxLength(32);
            entity.Property(e => e.CreatedAt)       .HasColumnName("CreatedAt");
            entity.Property(e => e.UserId)          .HasColumnName("UserId")           .HasMaxLength(128);
            entity.Property(e => e.HealthScore)     .HasColumnName("HealthScore");
            entity.Property(e => e.RepositoryName)  .HasColumnName("RepositoryName")   .HasMaxLength(256);

            // Serialize Result as JSON (avoids a complex relational schema for the demo)
            entity.Property(e => e.Result)
                .HasColumnName("Result")
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<ScanResult>(v, (JsonSerializerOptions?)null)
                );

            // Indexes for fast lookups
            entity.HasIndex(e => e.UserId)   .HasDatabaseName("IX_ScanStates_UserId");
            entity.HasIndex(e => e.Status)   .HasDatabaseName("IX_ScanStates_Status");
            entity.HasIndex(e => e.CreatedAt).HasDatabaseName("IX_ScanStates_CreatedAt");
        });

        // ── LocalUser ──────────────────────────────────────────────────
        modelBuilder.Entity<LocalUser>(entity =>
        {
            entity.HasKey(e => e.SupabaseId);
            entity.ToTable("LocalUsers");

            entity.Property(e => e.SupabaseId)   .HasColumnName("SupabaseId")   .IsRequired().HasMaxLength(128);
            entity.Property(e => e.Email)        .HasColumnName("Email")        .IsRequired().HasMaxLength(256);
            entity.Property(e => e.DisplayName)  .HasColumnName("DisplayName")  .HasMaxLength(100);
            entity.Property(e => e.PlanType)     .HasColumnName("PlanType")     .HasMaxLength(16).HasDefaultValue("FREE");
            entity.Property(e => e.ScansThisMonth).HasColumnName("ScansThisMonth").HasDefaultValue(0);
            entity.Property(e => e.LastLogin)    .HasColumnName("LastLogin");
            entity.Property(e => e.PlanResetDate).HasColumnName("PlanResetDate");
            entity.Property(e => e.IsAdmin)      .HasColumnName("IsAdmin")      .HasDefaultValue(false);
            entity.Property(e => e.IsActive)     .HasColumnName("IsActive")     .HasDefaultValue(true);

            entity.HasIndex(e => e.Email).HasDatabaseName("IX_LocalUsers_Email").IsUnique();

            // Navigation: one user → many API keys
            entity.HasMany<ApiKey>()
                  .WithOne()
                  .HasForeignKey(k => k.UserId)
                  .HasPrincipalKey(u => u.SupabaseId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ── ApiKey ─────────────────────────────────────────────────────
        modelBuilder.Entity<ApiKey>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.ToTable("ApiKeys");

            entity.Property(e => e.Id)       .HasColumnName("Id")       .IsRequired().HasMaxLength(64);
            entity.Property(e => e.UserId)   .HasColumnName("UserId")   .IsRequired().HasMaxLength(128);
            entity.Property(e => e.Name)     .HasColumnName("Name")     .IsRequired().HasMaxLength(100);
            entity.Property(e => e.KeyValue) .HasColumnName("KeyValue") .IsRequired().HasMaxLength(128);
            entity.Property(e => e.CreatedAt).HasColumnName("CreatedAt");
            entity.Property(e => e.LastUsed) .HasColumnName("LastUsed");

            entity.HasIndex(e => e.UserId).HasDatabaseName("IX_ApiKeys_UserId");
        });
    }
}
