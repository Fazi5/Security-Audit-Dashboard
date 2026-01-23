using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using SecurityAuditDashboard.Infrastructure.Data;

namespace SecurityAuditDashboard.Web.BackgroundServices;

/// <summary>
/// Background service that periodically cleans up old logs and events
/// Demonstrates: IHostedService, BackgroundService, scheduled tasks, database maintenance
/// </summary>
public class LogCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<LogCleanupService> _logger;
    
    // Run cleanup once per day
    private readonly TimeSpan _cleanupInterval = TimeSpan.FromHours(24);
    
    // Retention periods (configurable in real app via IConfiguration)
    private readonly int _auditLogRetentionDays = 90;
    private readonly int _loginAttemptRetentionDays = 30;
    private readonly int _resolvedEventRetentionDays = 60;
    private readonly int _resolvedThreatRetentionDays = 90;

    public LogCleanupService(
        IServiceProvider serviceProvider,
        ILogger<LogCleanupService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Log Cleanup Service is starting.");

        // Initial delay - wait until midnight (or 1 minute for demo)
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PerformCleanupAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during log cleanup.");
            }

            await Task.Delay(_cleanupInterval, stoppingToken);
        }

        _logger.LogInformation("Log Cleanup Service is stopping.");
    }

    private async Task PerformCleanupAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting log cleanup at {Time}", DateTime.UtcNow);

        using var scope = _serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var totalDeleted = 0;

        // Cleanup old audit logs
        var auditLogCutoff = DateTime.UtcNow.AddDays(-_auditLogRetentionDays);
        var oldAuditLogs = await context.AuditLogs
            .Where(l => l.Timestamp < auditLogCutoff)
            .CountAsync(cancellationToken);

        if (oldAuditLogs > 0)
        {
            var deleted = await context.AuditLogs
                .Where(l => l.Timestamp < auditLogCutoff)
                .ExecuteDeleteAsync(cancellationToken);
            
            totalDeleted += deleted;
            _logger.LogInformation("Deleted {Count} audit logs older than {Days} days", 
                deleted, _auditLogRetentionDays);
        }

        // Cleanup old login attempts
        var loginAttemptCutoff = DateTime.UtcNow.AddDays(-_loginAttemptRetentionDays);
        var oldLoginAttempts = await context.LoginAttempts
            .Where(l => l.Timestamp < loginAttemptCutoff)
            .CountAsync(cancellationToken);

        if (oldLoginAttempts > 0)
        {
            var deleted = await context.LoginAttempts
                .Where(l => l.Timestamp < loginAttemptCutoff)
                .ExecuteDeleteAsync(cancellationToken);
            
            totalDeleted += deleted;
            _logger.LogInformation("Deleted {Count} login attempts older than {Days} days", 
                deleted, _loginAttemptRetentionDays);
        }

        // Cleanup resolved security events (keep unresolved ones)
        var eventCutoff = DateTime.UtcNow.AddDays(-_resolvedEventRetentionDays);
        var oldEvents = await context.SecurityEvents
            .Where(e => e.IsResolved && e.ResolvedAt < eventCutoff)
            .CountAsync(cancellationToken);

        if (oldEvents > 0)
        {
            var deleted = await context.SecurityEvents
                .Where(e => e.IsResolved && e.ResolvedAt < eventCutoff)
                .ExecuteDeleteAsync(cancellationToken);
            
            totalDeleted += deleted;
            _logger.LogInformation("Deleted {Count} resolved events older than {Days} days", 
                deleted, _resolvedEventRetentionDays);
        }

        // Cleanup resolved threat alerts
        var threatCutoff = DateTime.UtcNow.AddDays(-_resolvedThreatRetentionDays);
        var oldThreats = await context.ThreatAlerts
            .Where(t => (t.Status == Core.Enums.ThreatStatus.Resolved || 
                        t.Status == Core.Enums.ThreatStatus.FalsePositive) && 
                        t.ResolvedAt < threatCutoff)
            .CountAsync(cancellationToken);

        if (oldThreats > 0)
        {
            var deleted = await context.ThreatAlerts
                .Where(t => (t.Status == Core.Enums.ThreatStatus.Resolved || 
                            t.Status == Core.Enums.ThreatStatus.FalsePositive) && 
                            t.ResolvedAt < threatCutoff)
                .ExecuteDeleteAsync(cancellationToken);
            
            totalDeleted += deleted;
            _logger.LogInformation("Deleted {Count} resolved threats older than {Days} days", 
                deleted, _resolvedThreatRetentionDays);
        }

        _logger.LogInformation(
            "Log cleanup completed. Total records deleted: {TotalDeleted}", 
            totalDeleted);
    }
}
