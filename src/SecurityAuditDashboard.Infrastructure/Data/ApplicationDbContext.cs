using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecurityAuditDashboard.Core.Entities;

namespace SecurityAuditDashboard.Infrastructure.Data;

/// <summary>
/// Application database context with Identity and security entities
/// </summary>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();
    public DbSet<ThreatAlert> ThreatAlerts => Set<ThreatAlert>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // AuditLog configuration
        builder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Timestamp);
            entity.Property(e => e.Action).HasMaxLength(200).IsRequired();
            entity.Property(e => e.IpAddress).HasMaxLength(50);
            entity.Property(e => e.UserAgent).HasMaxLength(500);
        });

        // SecurityEvent configuration
        builder.Entity<SecurityEvent>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.Severity);
            entity.HasIndex(e => e.IsResolved);
            entity.Property(e => e.Description).HasMaxLength(1000).IsRequired();
            entity.Property(e => e.Source).HasMaxLength(200);
        });

        // LoginAttempt configuration
        builder.Entity<LoginAttempt>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.IpAddress);
            entity.HasIndex(e => e.Timestamp);
            entity.Property(e => e.IpAddress).HasMaxLength(50).IsRequired();
            entity.Property(e => e.UserAgent).HasMaxLength(500);
            entity.Property(e => e.FailureReason).HasMaxLength(500);
        });

        // ThreatAlert configuration
        builder.Entity<ThreatAlert>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => e.DetectedAt);
            entity.Property(e => e.ThreatType).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Source).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(1000).IsRequired();
        });
    }
}
