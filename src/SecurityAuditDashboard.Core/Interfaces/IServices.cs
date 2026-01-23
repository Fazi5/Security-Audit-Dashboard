using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;

namespace SecurityAuditDashboard.Core.Interfaces;

/// <summary>
/// Service for managing audit logs
/// </summary>
public interface IAuditService
{
    Task LogActivityAsync(string userId, string userName, string action, string? details, string ipAddress, string? userAgent);
    Task<IEnumerable<AuditLog>> GetAuditLogsAsync(DateTime? from = null, DateTime? to = null, string? userId = null);
    Task<IEnumerable<AuditLog>> GetRecentLogsAsync(int count = 50);
}

/// <summary>
/// Service for detecting and managing security threats
/// </summary>
public interface IThreatDetectionService
{
    Task<bool> AnalyzeLoginAttemptAsync(LoginAttempt attempt);
    Task<ThreatAlert?> DetectBruteForceAsync(string userId, string ipAddress);
    Task<IEnumerable<ThreatAlert>> GetActiveThreatsAsync();
    Task<ThreatAlert> CreateThreatAlertAsync(string threatType, string source, EventSeverity severity, string description);
    Task ResolveThreatAsync(int threatId, string resolvedBy, string resolutionNotes);
}

/// <summary>
/// Service for generating security reports
/// </summary>
public interface ISecurityReportService
{
    Task<byte[]> GenerateSecurityReportAsync(DateTime from, DateTime to);
    Task<DashboardStats> GetDashboardStatsAsync();
}

/// <summary>
/// Service for real-time notifications
/// </summary>
public interface INotificationService
{
    Task NotifySecurityEventAsync(SecurityEvent securityEvent);
    Task NotifyThreatAlertAsync(ThreatAlert threat);
}

/// <summary>
/// Dashboard statistics DTO
/// </summary>
public record DashboardStats(
    int TotalEvents,
    int CriticalEvents,
    int FailedLogins,
    int ActiveThreats,
    int ResolvedThreats,
    DateTime LastScanTime
);
