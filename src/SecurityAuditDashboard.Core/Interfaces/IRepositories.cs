using SecurityAuditDashboard.Core.Entities;

namespace SecurityAuditDashboard.Core.Interfaces;

/// <summary>
/// Generic repository interface for data access
/// </summary>
public interface IRepository<T> where T : class
{
    Task<T?> GetByIdAsync(int id);
    Task<IEnumerable<T>> GetAllAsync();
    Task<T> AddAsync(T entity);
    Task UpdateAsync(T entity);
    Task DeleteAsync(int id);
}

/// <summary>
/// Repository for audit logs with specific query methods
/// </summary>
public interface IAuditLogRepository : IRepository<AuditLog>
{
    Task<IEnumerable<AuditLog>> GetByUserIdAsync(string userId);
    Task<IEnumerable<AuditLog>> GetByDateRangeAsync(DateTime from, DateTime to);
    Task<IEnumerable<AuditLog>> GetRecentAsync(int count);
}

/// <summary>
/// Repository for security events
/// </summary>
public interface ISecurityEventRepository : IRepository<SecurityEvent>
{
    Task<IEnumerable<SecurityEvent>> GetUnresolvedAsync();
    Task<IEnumerable<SecurityEvent>> GetBySeverityAsync(Core.Enums.EventSeverity severity);
    Task<int> GetCountByDateRangeAsync(DateTime from, DateTime to);
}

/// <summary>
/// Repository for login attempts
/// </summary>
public interface ILoginAttemptRepository : IRepository<LoginAttempt>
{
    Task<IEnumerable<LoginAttempt>> GetByUserIdAsync(string userId, int count = 10);
    Task<IEnumerable<LoginAttempt>> GetFailedAttemptsAsync(string ipAddress, TimeSpan timeWindow);
    Task<int> GetFailedCountAsync(string userId, TimeSpan timeWindow);
}

/// <summary>
/// Repository for threat alerts
/// </summary>
public interface IThreatAlertRepository : IRepository<ThreatAlert>
{
    Task<IEnumerable<ThreatAlert>> GetActiveAlertsAsync();
    Task<IEnumerable<ThreatAlert>> GetByStatusAsync(Core.Enums.ThreatStatus status);
}
