using Microsoft.EntityFrameworkCore;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;
using SecurityAuditDashboard.Infrastructure.Data;
using SecurityAuditDashboard.Infrastructure.Repositories;

namespace SecurityAuditDashboard.Tests;

/// <summary>
/// Integration tests for repositories using EF Core InMemory database
/// Demonstrates: In-memory database testing, repository pattern testing
/// </summary>
public class RepositoryTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly AuditLogRepository _auditLogRepository;
    private readonly ThreatAlertRepository _threatAlertRepository;

    public RepositoryTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _auditLogRepository = new AuditLogRepository(_context);
        _threatAlertRepository = new ThreatAlertRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region AuditLogRepository Tests

    [Fact]
    public async Task AuditLogRepository_AddAsync_ShouldPersistLog()
    {
        // Arrange
        var log = new AuditLog
        {
            UserId = "user1",
            UserName = "Test User",
            Action = "Login",
            IpAddress = "127.0.0.1",
            Timestamp = DateTime.UtcNow
        };

        // Act
        var result = await _auditLogRepository.AddAsync(log);

        // Assert
        Assert.True(result.Id > 0);
        var retrieved = await _auditLogRepository.GetByIdAsync(result.Id);
        Assert.NotNull(retrieved);
        Assert.Equal("Login", retrieved.Action);
    }

    [Fact]
    public async Task AuditLogRepository_GetRecentAsync_ShouldReturnOrderedByTimestamp()
    {
        // Arrange
        await _auditLogRepository.AddAsync(new AuditLog 
        { 
            UserId = "user1", 
            UserName = "User1",
            Action = "Old", 
            IpAddress = "127.0.0.1",
            Timestamp = DateTime.UtcNow.AddHours(-2) 
        });
        await _auditLogRepository.AddAsync(new AuditLog 
        { 
            UserId = "user2", 
            UserName = "User2",
            Action = "New", 
            IpAddress = "127.0.0.1",
            Timestamp = DateTime.UtcNow 
        });

        // Act
        var result = await _auditLogRepository.GetRecentAsync(2);

        // Assert
        var logs = result.ToList();
        Assert.Equal(2, logs.Count);
        Assert.Equal("New", logs[0].Action); // Most recent first
        Assert.Equal("Old", logs[1].Action);
    }

    [Fact]
    public async Task AuditLogRepository_GetByUserIdAsync_ShouldFilterByUser()
    {
        // Arrange
        await _auditLogRepository.AddAsync(new AuditLog 
        { 
            UserId = "user1", 
            UserName = "User1",
            Action = "Action1", 
            IpAddress = "127.0.0.1"
        });
        await _auditLogRepository.AddAsync(new AuditLog 
        { 
            UserId = "user2", 
            UserName = "User2",
            Action = "Action2", 
            IpAddress = "127.0.0.1"
        });

        // Act
        var result = await _auditLogRepository.GetByUserIdAsync("user1");

        // Assert
        Assert.Single(result);
        Assert.Equal("Action1", result.First().Action);
    }

    [Fact]
    public async Task AuditLogRepository_GetByDateRangeAsync_ShouldFilterByDate()
    {
        // Arrange
        var now = DateTime.UtcNow;
        await _auditLogRepository.AddAsync(new AuditLog 
        { 
            UserId = "user1", 
            UserName = "User1",
            Action = "InRange", 
            IpAddress = "127.0.0.1",
            Timestamp = now.AddDays(-3) 
        });
        await _auditLogRepository.AddAsync(new AuditLog 
        { 
            UserId = "user1", 
            UserName = "User1",
            Action = "OutOfRange", 
            IpAddress = "127.0.0.1",
            Timestamp = now.AddDays(-10) 
        });

        // Act
        var result = await _auditLogRepository.GetByDateRangeAsync(now.AddDays(-5), now);

        // Assert
        Assert.Single(result);
        Assert.Equal("InRange", result.First().Action);
    }

    #endregion

    #region ThreatAlertRepository Tests

    [Fact]
    public async Task ThreatAlertRepository_GetActiveAlertsAsync_ShouldExcludeResolved()
    {
        // Arrange
        await _threatAlertRepository.AddAsync(new ThreatAlert
        {
            ThreatType = "Active",
            Source = "test",
            Description = "Active threat",
            Status = ThreatStatus.New,
            Severity = EventSeverity.High
        });
        await _threatAlertRepository.AddAsync(new ThreatAlert
        {
            ThreatType = "Resolved",
            Source = "test",
            Description = "Resolved threat",
            Status = ThreatStatus.Resolved,
            Severity = EventSeverity.Medium
        });

        // Act
        var result = await _threatAlertRepository.GetActiveAlertsAsync();

        // Assert
        Assert.Single(result);
        Assert.Equal("Active", result.First().ThreatType);
    }

    [Fact]
    public async Task ThreatAlertRepository_GetByStatusAsync_ShouldFilterByStatus()
    {
        // Arrange
        await _threatAlertRepository.AddAsync(new ThreatAlert
        {
            ThreatType = "New1",
            Source = "test",
            Description = "New threat",
            Status = ThreatStatus.New,
            Severity = EventSeverity.High
        });
        await _threatAlertRepository.AddAsync(new ThreatAlert
        {
            ThreatType = "Investigating",
            Source = "test",
            Description = "Under investigation",
            Status = ThreatStatus.Investigating,
            Severity = EventSeverity.Medium
        });

        // Act
        var result = await _threatAlertRepository.GetByStatusAsync(ThreatStatus.Investigating);

        // Assert
        Assert.Single(result);
        Assert.Equal("Investigating", result.First().ThreatType);
    }

    [Fact]
    public async Task ThreatAlertRepository_UpdateAsync_ShouldPersistChanges()
    {
        // Arrange
        var alert = await _threatAlertRepository.AddAsync(new ThreatAlert
        {
            ThreatType = "Test",
            Source = "test",
            Description = "Test threat",
            Status = ThreatStatus.New,
            Severity = EventSeverity.High
        });

        // Act
        alert.Status = ThreatStatus.Resolved;
        alert.ResolvedAt = DateTime.UtcNow;
        await _threatAlertRepository.UpdateAsync(alert);

        // Assert
        var updated = await _threatAlertRepository.GetByIdAsync(alert.Id);
        Assert.NotNull(updated);
        Assert.Equal(ThreatStatus.Resolved, updated.Status);
        Assert.NotNull(updated.ResolvedAt);
    }

    [Fact]
    public async Task ThreatAlertRepository_DeleteAsync_ShouldRemoveAlert()
    {
        // Arrange
        var alert = await _threatAlertRepository.AddAsync(new ThreatAlert
        {
            ThreatType = "ToDelete",
            Source = "test",
            Description = "Will be deleted",
            Status = ThreatStatus.New,
            Severity = EventSeverity.Low
        });

        // Act
        await _threatAlertRepository.DeleteAsync(alert.Id);

        // Assert
        var deleted = await _threatAlertRepository.GetByIdAsync(alert.Id);
        Assert.Null(deleted);
    }

    #endregion
}
