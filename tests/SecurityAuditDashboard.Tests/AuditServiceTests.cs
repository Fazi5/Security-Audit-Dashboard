using Moq;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;
using SecurityAuditDashboard.Core.Interfaces;
using SecurityAuditDashboard.Infrastructure.Services;

namespace SecurityAuditDashboard.Tests;

/// <summary>
/// Unit tests for AuditService
/// Demonstrates: Mocking with Moq, testing async methods, verifying interactions
/// </summary>
public class AuditServiceTests
{
    private readonly Mock<IAuditLogRepository> _mockAuditLogRepository;
    private readonly AuditService _auditService;

    public AuditServiceTests()
    {
        _mockAuditLogRepository = new Mock<IAuditLogRepository>();
        _auditService = new AuditService(_mockAuditLogRepository.Object);
    }

    [Fact]
    public async Task LogActivityAsync_ShouldCreateAuditLog_WithCorrectProperties()
    {
        // Arrange
        var userId = "user123";
        var userName = "John Doe";
        var action = "Login";
        var details = "Successful login";
        var ipAddress = "192.168.1.1";
        var userAgent = "Mozilla/5.0";

        AuditLog? capturedLog = null;
        _mockAuditLogRepository
            .Setup(r => r.AddAsync(It.IsAny<AuditLog>()))
            .Callback<AuditLog>(log => capturedLog = log)
            .ReturnsAsync((AuditLog log) => log);

        // Act
        await _auditService.LogActivityAsync(userId, userName, action, details, ipAddress, userAgent);

        // Assert
        Assert.NotNull(capturedLog);
        Assert.Equal(userId, capturedLog.UserId);
        Assert.Equal(userName, capturedLog.UserName);
        Assert.Equal(action, capturedLog.Action);
        Assert.Equal(details, capturedLog.Details);
        Assert.Equal(ipAddress, capturedLog.IpAddress);
        Assert.Equal(userAgent, capturedLog.UserAgent);
        Assert.True(capturedLog.IsSuccessful);
        
        _mockAuditLogRepository.Verify(r => r.AddAsync(It.IsAny<AuditLog>()), Times.Once);
    }

    [Fact]
    public async Task GetAuditLogsAsync_WithDateRange_ShouldCallGetByDateRange()
    {
        // Arrange
        var from = DateTime.UtcNow.AddDays(-7);
        var to = DateTime.UtcNow;
        var expectedLogs = new List<AuditLog>
        {
            new() { Id = 1, Action = "Login", Timestamp = DateTime.UtcNow.AddDays(-1) },
            new() { Id = 2, Action = "Logout", Timestamp = DateTime.UtcNow.AddDays(-2) }
        };

        _mockAuditLogRepository
            .Setup(r => r.GetByDateRangeAsync(from, to))
            .ReturnsAsync(expectedLogs);

        // Act
        var result = await _auditService.GetAuditLogsAsync(from, to);

        // Assert
        Assert.Equal(2, result.Count());
        _mockAuditLogRepository.Verify(r => r.GetByDateRangeAsync(from, to), Times.Once);
    }

    [Fact]
    public async Task GetAuditLogsAsync_WithUserId_ShouldCallGetByUserId()
    {
        // Arrange
        var userId = "user123";
        var expectedLogs = new List<AuditLog>
        {
            new() { Id = 1, UserId = userId, Action = "Login" }
        };

        _mockAuditLogRepository
            .Setup(r => r.GetByUserIdAsync(userId))
            .ReturnsAsync(expectedLogs);

        // Act
        var result = await _auditService.GetAuditLogsAsync(userId: userId);

        // Assert
        Assert.Single(result);
        _mockAuditLogRepository.Verify(r => r.GetByUserIdAsync(userId), Times.Once);
    }

    [Fact]
    public async Task GetRecentLogsAsync_ShouldReturnSpecifiedCount()
    {
        // Arrange
        var count = 10;
        var expectedLogs = Enumerable.Range(1, count)
            .Select(i => new AuditLog { Id = i, Action = $"Action{i}" })
            .ToList();

        _mockAuditLogRepository
            .Setup(r => r.GetRecentAsync(count))
            .ReturnsAsync(expectedLogs);

        // Act
        var result = await _auditService.GetRecentLogsAsync(count);

        // Assert
        Assert.Equal(count, result.Count());
        _mockAuditLogRepository.Verify(r => r.GetRecentAsync(count), Times.Once);
    }
}
