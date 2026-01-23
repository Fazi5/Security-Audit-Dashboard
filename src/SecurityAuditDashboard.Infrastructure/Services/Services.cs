using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;
using SecurityAuditDashboard.Core.Interfaces;

namespace SecurityAuditDashboard.Infrastructure.Services;

/// <summary>
/// Service for managing audit logs
/// </summary>
public class AuditService : IAuditService
{
    private readonly IAuditLogRepository _auditLogRepository;

    public AuditService(IAuditLogRepository auditLogRepository)
    {
        _auditLogRepository = auditLogRepository;
    }

    public async Task LogActivityAsync(string userId, string userName, string action, string? details, string ipAddress, string? userAgent)
    {
        var log = new AuditLog
        {
            UserId = userId,
            UserName = userName,
            Action = action,
            Details = details,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTime.UtcNow,
            IsSuccessful = true
        };

        await _auditLogRepository.AddAsync(log);
    }

    public async Task<IEnumerable<AuditLog>> GetAuditLogsAsync(DateTime? from = null, DateTime? to = null, string? userId = null)
    {
        if (from.HasValue && to.HasValue)
        {
            return await _auditLogRepository.GetByDateRangeAsync(from.Value, to.Value);
        }
        
        if (!string.IsNullOrEmpty(userId))
        {
            return await _auditLogRepository.GetByUserIdAsync(userId);
        }

        return await _auditLogRepository.GetAllAsync();
    }

    public async Task<IEnumerable<AuditLog>> GetRecentLogsAsync(int count = 50)
    {
        return await _auditLogRepository.GetRecentAsync(count);
    }
}

/// <summary>
/// Service for detecting and managing security threats
/// </summary>
public class ThreatDetectionService : IThreatDetectionService
{
    private readonly IThreatAlertRepository _threatAlertRepository;
    private readonly ILoginAttemptRepository _loginAttemptRepository;
    private readonly ISecurityEventRepository _securityEventRepository;

    // Configuration: Number of failed attempts before flagging as brute force
    private const int BruteForceThreshold = 5;
    private static readonly TimeSpan BruteForceWindow = TimeSpan.FromMinutes(15);

    public ThreatDetectionService(
        IThreatAlertRepository threatAlertRepository,
        ILoginAttemptRepository loginAttemptRepository,
        ISecurityEventRepository securityEventRepository)
    {
        _threatAlertRepository = threatAlertRepository;
        _loginAttemptRepository = loginAttemptRepository;
        _securityEventRepository = securityEventRepository;
    }

    public async Task<bool> AnalyzeLoginAttemptAsync(LoginAttempt attempt)
    {
        await _loginAttemptRepository.AddAsync(attempt);

        if (!attempt.Success)
        {
            // Check for brute force attack
            var threat = await DetectBruteForceAsync(attempt.UserId, attempt.IpAddress);
            return threat != null;
        }

        return false;
    }

    public async Task<ThreatAlert?> DetectBruteForceAsync(string userId, string ipAddress)
    {
        var failedCount = await _loginAttemptRepository.GetFailedCountAsync(userId, BruteForceWindow);

        if (failedCount >= BruteForceThreshold)
        {
            var existingAlerts = await _threatAlertRepository.GetActiveAlertsAsync();
            var hasExistingAlert = existingAlerts.Any(a => 
                a.ThreatType == "Brute Force Attack" && 
                a.Source == ipAddress &&
                a.Status != ThreatStatus.Resolved);

            if (!hasExistingAlert)
            {
                return await CreateThreatAlertAsync(
                    "Brute Force Attack",
                    ipAddress,
                    EventSeverity.High,
                    $"Multiple failed login attempts ({failedCount}) detected from IP {ipAddress} for user {userId} within {BruteForceWindow.TotalMinutes} minutes."
                );
            }
        }

        return null;
    }

    public async Task<IEnumerable<ThreatAlert>> GetActiveThreatsAsync()
    {
        return await _threatAlertRepository.GetActiveAlertsAsync();
    }

    public async Task<ThreatAlert> CreateThreatAlertAsync(string threatType, string source, EventSeverity severity, string description)
    {
        var alert = new ThreatAlert
        {
            ThreatType = threatType,
            Source = source,
            Severity = severity,
            Description = description,
            Status = ThreatStatus.New,
            DetectedAt = DateTime.UtcNow
        };

        return await _threatAlertRepository.AddAsync(alert);
    }

    public async Task ResolveThreatAsync(int threatId, string resolvedBy, string resolutionNotes)
    {
        var threat = await _threatAlertRepository.GetByIdAsync(threatId);
        if (threat != null)
        {
            threat.Status = ThreatStatus.Resolved;
            threat.ResolvedAt = DateTime.UtcNow;
            threat.ResolutionNotes = resolutionNotes;
            threat.AssignedTo = resolvedBy;
            await _threatAlertRepository.UpdateAsync(threat);
        }
    }
}

/// <summary>
/// Service for generating security reports and dashboard statistics
/// </summary>
public class SecurityReportService : ISecurityReportService
{
    private readonly ISecurityEventRepository _securityEventRepository;
    private readonly IThreatAlertRepository _threatAlertRepository;
    private readonly ILoginAttemptRepository _loginAttemptRepository;

    public SecurityReportService(
        ISecurityEventRepository securityEventRepository,
        IThreatAlertRepository threatAlertRepository,
        ILoginAttemptRepository loginAttemptRepository)
    {
        _securityEventRepository = securityEventRepository;
        _threatAlertRepository = threatAlertRepository;
        _loginAttemptRepository = loginAttemptRepository;
    }

    public async Task<DashboardStats> GetDashboardStatsAsync()
    {
        var allEvents = await _securityEventRepository.GetAllAsync();
        var criticalEvents = await _securityEventRepository.GetBySeverityAsync(EventSeverity.Critical);
        var allAttempts = await _loginAttemptRepository.GetAllAsync();
        var failedLogins = allAttempts.Count(a => !a.Success);
        var activeThreats = await _threatAlertRepository.GetActiveAlertsAsync();
        var resolvedThreats = await _threatAlertRepository.GetByStatusAsync(ThreatStatus.Resolved);

        return new DashboardStats(
            TotalEvents: allEvents.Count(),
            CriticalEvents: criticalEvents.Count(),
            FailedLogins: failedLogins,
            ActiveThreats: activeThreats.Count(),
            ResolvedThreats: resolvedThreats.Count(),
            LastScanTime: DateTime.UtcNow
        );
    }

    public async Task<byte[]> GenerateSecurityReportAsync(DateTime from, DateTime to)
    {
        // Simple text report for now - can be enhanced with PDF generation
        var eventCount = await _securityEventRepository.GetCountByDateRangeAsync(from, to);
        var report = $"""
            Security Report
            ===============
            Period: {from:yyyy-MM-dd} to {to:yyyy-MM-dd}
            Total Events: {eventCount}
            Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC
            """;

        return System.Text.Encoding.UTF8.GetBytes(report);
    }
}
