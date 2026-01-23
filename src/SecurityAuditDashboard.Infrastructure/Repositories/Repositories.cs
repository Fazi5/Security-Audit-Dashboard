using Microsoft.EntityFrameworkCore;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;
using SecurityAuditDashboard.Core.Interfaces;
using SecurityAuditDashboard.Infrastructure.Data;

namespace SecurityAuditDashboard.Infrastructure.Repositories;

/// <summary>
/// Repository implementation for audit logs
/// </summary>
public class AuditLogRepository : IAuditLogRepository
{
    private readonly ApplicationDbContext _context;

    public AuditLogRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<AuditLog?> GetByIdAsync(int id)
    {
        return await _context.AuditLogs.FindAsync(id);
    }

    public async Task<IEnumerable<AuditLog>> GetAllAsync()
    {
        return await _context.AuditLogs
            .OrderByDescending(a => a.Timestamp)
            .ToListAsync();
    }

    public async Task<AuditLog> AddAsync(AuditLog entity)
    {
        _context.AuditLogs.Add(entity);
        await _context.SaveChangesAsync();
        return entity;
    }

    public async Task UpdateAsync(AuditLog entity)
    {
        _context.Entry(entity).State = EntityState.Modified;
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        var entity = await _context.AuditLogs.FindAsync(id);
        if (entity != null)
        {
            _context.AuditLogs.Remove(entity);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<IEnumerable<AuditLog>> GetByUserIdAsync(string userId)
    {
        return await _context.AuditLogs
            .Where(a => a.UserId == userId)
            .OrderByDescending(a => a.Timestamp)
            .ToListAsync();
    }

    public async Task<IEnumerable<AuditLog>> GetByDateRangeAsync(DateTime from, DateTime to)
    {
        return await _context.AuditLogs
            .Where(a => a.Timestamp >= from && a.Timestamp <= to)
            .OrderByDescending(a => a.Timestamp)
            .ToListAsync();
    }

    public async Task<IEnumerable<AuditLog>> GetRecentAsync(int count)
    {
        return await _context.AuditLogs
            .OrderByDescending(a => a.Timestamp)
            .Take(count)
            .ToListAsync();
    }
}

/// <summary>
/// Repository implementation for security events
/// </summary>
public class SecurityEventRepository : ISecurityEventRepository
{
    private readonly ApplicationDbContext _context;

    public SecurityEventRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<SecurityEvent?> GetByIdAsync(int id)
    {
        return await _context.SecurityEvents.FindAsync(id);
    }

    public async Task<IEnumerable<SecurityEvent>> GetAllAsync()
    {
        return await _context.SecurityEvents
            .OrderByDescending(e => e.Timestamp)
            .ToListAsync();
    }

    public async Task<SecurityEvent> AddAsync(SecurityEvent entity)
    {
        _context.SecurityEvents.Add(entity);
        await _context.SaveChangesAsync();
        return entity;
    }

    public async Task UpdateAsync(SecurityEvent entity)
    {
        _context.Entry(entity).State = EntityState.Modified;
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        var entity = await _context.SecurityEvents.FindAsync(id);
        if (entity != null)
        {
            _context.SecurityEvents.Remove(entity);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<IEnumerable<SecurityEvent>> GetUnresolvedAsync()
    {
        return await _context.SecurityEvents
            .Where(e => !e.IsResolved)
            .OrderByDescending(e => e.Severity)
            .ThenByDescending(e => e.Timestamp)
            .ToListAsync();
    }

    public async Task<IEnumerable<SecurityEvent>> GetBySeverityAsync(EventSeverity severity)
    {
        return await _context.SecurityEvents
            .Where(e => e.Severity == severity)
            .OrderByDescending(e => e.Timestamp)
            .ToListAsync();
    }

    public async Task<int> GetCountByDateRangeAsync(DateTime from, DateTime to)
    {
        return await _context.SecurityEvents
            .Where(e => e.Timestamp >= from && e.Timestamp <= to)
            .CountAsync();
    }
}

/// <summary>
/// Repository implementation for login attempts
/// </summary>
public class LoginAttemptRepository : ILoginAttemptRepository
{
    private readonly ApplicationDbContext _context;

    public LoginAttemptRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<LoginAttempt?> GetByIdAsync(int id)
    {
        return await _context.LoginAttempts.FindAsync(id);
    }

    public async Task<IEnumerable<LoginAttempt>> GetAllAsync()
    {
        return await _context.LoginAttempts
            .OrderByDescending(l => l.Timestamp)
            .ToListAsync();
    }

    public async Task<LoginAttempt> AddAsync(LoginAttempt entity)
    {
        _context.LoginAttempts.Add(entity);
        await _context.SaveChangesAsync();
        return entity;
    }

    public async Task UpdateAsync(LoginAttempt entity)
    {
        _context.Entry(entity).State = EntityState.Modified;
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        var entity = await _context.LoginAttempts.FindAsync(id);
        if (entity != null)
        {
            _context.LoginAttempts.Remove(entity);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<IEnumerable<LoginAttempt>> GetByUserIdAsync(string userId, int count = 10)
    {
        return await _context.LoginAttempts
            .Where(l => l.UserId == userId)
            .OrderByDescending(l => l.Timestamp)
            .Take(count)
            .ToListAsync();
    }

    public async Task<IEnumerable<LoginAttempt>> GetFailedAttemptsAsync(string ipAddress, TimeSpan timeWindow)
    {
        var cutoff = DateTime.UtcNow - timeWindow;
        return await _context.LoginAttempts
            .Where(l => l.IpAddress == ipAddress && !l.Success && l.Timestamp >= cutoff)
            .OrderByDescending(l => l.Timestamp)
            .ToListAsync();
    }

    public async Task<int> GetFailedCountAsync(string userId, TimeSpan timeWindow)
    {
        var cutoff = DateTime.UtcNow - timeWindow;
        return await _context.LoginAttempts
            .Where(l => l.UserId == userId && !l.Success && l.Timestamp >= cutoff)
            .CountAsync();
    }
}

/// <summary>
/// Repository implementation for threat alerts
/// </summary>
public class ThreatAlertRepository : IThreatAlertRepository
{
    private readonly ApplicationDbContext _context;

    public ThreatAlertRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<ThreatAlert?> GetByIdAsync(int id)
    {
        return await _context.ThreatAlerts.FindAsync(id);
    }

    public async Task<IEnumerable<ThreatAlert>> GetAllAsync()
    {
        return await _context.ThreatAlerts
            .OrderByDescending(t => t.DetectedAt)
            .ToListAsync();
    }

    public async Task<ThreatAlert> AddAsync(ThreatAlert entity)
    {
        _context.ThreatAlerts.Add(entity);
        await _context.SaveChangesAsync();
        return entity;
    }

    public async Task UpdateAsync(ThreatAlert entity)
    {
        _context.Entry(entity).State = EntityState.Modified;
        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        var entity = await _context.ThreatAlerts.FindAsync(id);
        if (entity != null)
        {
            _context.ThreatAlerts.Remove(entity);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<IEnumerable<ThreatAlert>> GetActiveAlertsAsync()
    {
        return await _context.ThreatAlerts
            .Where(t => t.Status != ThreatStatus.Resolved && t.Status != ThreatStatus.FalsePositive)
            .OrderByDescending(t => t.Severity)
            .ThenByDescending(t => t.DetectedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<ThreatAlert>> GetByStatusAsync(ThreatStatus status)
    {
        return await _context.ThreatAlerts
            .Where(t => t.Status == status)
            .OrderByDescending(t => t.DetectedAt)
            .ToListAsync();
    }
}
