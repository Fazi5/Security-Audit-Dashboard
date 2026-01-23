using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;
using SecurityAuditDashboard.Core.Interfaces;

namespace SecurityAuditDashboard.Web.BackgroundServices;

/// <summary>
/// Background service that performs periodic security scans
/// Demonstrates: IHostedService, BackgroundService, Timer, DI with scoped services
/// </summary>
public class SecurityScanService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SecurityScanService> _logger;
    private readonly TimeSpan _scanInterval = TimeSpan.FromMinutes(5);
    
    // For demo purposes, we'll also track a shorter interval for visibility
    private DateTime _lastScanTime = DateTime.MinValue;

    public SecurityScanService(
        IServiceProvider serviceProvider,
        ILogger<SecurityScanService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Security Scan Service is starting.");

        // Initial delay to let the application start up
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PerformSecurityScanAsync(stoppingToken);
                _lastScanTime = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during security scan.");
            }

            await Task.Delay(_scanInterval, stoppingToken);
        }

        _logger.LogInformation("Security Scan Service is stopping.");
    }

    private async Task PerformSecurityScanAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting security scan at {Time}", DateTime.UtcNow);

        // Create a scope to resolve scoped services (DbContext, repositories)
        using var scope = _serviceProvider.CreateScope();
        
        var loginAttemptRepo = scope.ServiceProvider.GetRequiredService<ILoginAttemptRepository>();
        var threatService = scope.ServiceProvider.GetRequiredService<IThreatDetectionService>();
        var securityEventRepo = scope.ServiceProvider.GetRequiredService<ISecurityEventRepository>();
        var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();

        // Scan 1: Check for brute force patterns
        await ScanForBruteForceAttacksAsync(loginAttemptRepo, threatService);

        // Scan 2: Check for unusual login patterns
        await ScanForUnusualPatternsAsync(loginAttemptRepo, securityEventRepo, notificationService);

        // Scan 3: Generate summary statistics
        await GenerateScanSummaryAsync(securityEventRepo, threatService);

        _logger.LogInformation("Security scan completed at {Time}", DateTime.UtcNow);
    }

    private async Task ScanForBruteForceAttacksAsync(
        ILoginAttemptRepository loginAttemptRepo,
        IThreatDetectionService threatService)
    {
        _logger.LogDebug("Scanning for brute force attacks...");

        // Get all failed login attempts in the last 15 minutes
        var recentAttempts = await loginAttemptRepo.GetAllAsync();
        var cutoff = DateTime.UtcNow.AddMinutes(-15);
        
        var failedAttempts = recentAttempts
            .Where(a => !a.Success && a.Timestamp >= cutoff)
            .GroupBy(a => a.IpAddress)
            .Where(g => g.Count() >= 5)
            .ToList();

        foreach (var group in failedAttempts)
        {
            _logger.LogWarning(
                "Potential brute force detected from IP {IpAddress}: {Count} failed attempts",
                group.Key, group.Count());

            // Create threat alert if one doesn't exist
            var activeThreats = await threatService.GetActiveThreatsAsync();
            var existingThreat = activeThreats.FirstOrDefault(t => 
                t.ThreatType == "Brute Force Attack" && 
                t.Source == group.Key);

            if (existingThreat == null)
            {
                await threatService.CreateThreatAlertAsync(
                    "Brute Force Attack",
                    group.Key,
                    EventSeverity.High,
                    $"Automated scan detected {group.Count()} failed login attempts from IP {group.Key} in the last 15 minutes."
                );
            }
        }
    }

    private async Task ScanForUnusualPatternsAsync(
        ILoginAttemptRepository loginAttemptRepo,
        ISecurityEventRepository securityEventRepo,
        INotificationService notificationService)
    {
        _logger.LogDebug("Scanning for unusual login patterns...");

        // Check for logins from new IP addresses
        var allAttempts = await loginAttemptRepo.GetAllAsync();
        var today = DateTime.UtcNow.Date;
        
        var newIpLogins = allAttempts
            .Where(a => a.Success && a.Timestamp >= today)
            .GroupBy(a => new { a.UserId, a.IpAddress })
            .Where(g => g.Count() == 1) // First time login from this IP
            .ToList();

        // Create security events for unusual patterns (only if significant)
        if (newIpLogins.Count > 5)
        {
            var securityEvent = new SecurityEvent
            {
                EventType = EventType.SuspiciousActivity,
                Severity = EventSeverity.Medium,
                Description = $"Detected {newIpLogins.Count} logins from new IP addresses today",
                Source = "SecurityScanService",
                Timestamp = DateTime.UtcNow
            };

            await securityEventRepo.AddAsync(securityEvent);
            await notificationService.NotifySecurityEventAsync(securityEvent);
        }
    }

    private async Task GenerateScanSummaryAsync(
        ISecurityEventRepository securityEventRepo,
        IThreatDetectionService threatService)
    {
        _logger.LogDebug("Generating scan summary...");

        var unresolvedEvents = await securityEventRepo.GetUnresolvedAsync();
        var activeThreats = await threatService.GetActiveThreatsAsync();

        _logger.LogInformation(
            "Scan Summary: {UnresolvedEvents} unresolved events, {ActiveThreats} active threats",
            unresolvedEvents.Count(),
            activeThreats.Count());
    }
}
