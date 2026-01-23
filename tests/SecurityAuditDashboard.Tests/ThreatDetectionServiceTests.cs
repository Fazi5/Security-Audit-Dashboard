using Moq;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Enums;
using SecurityAuditDashboard.Core.Interfaces;
using SecurityAuditDashboard.Infrastructure.Services;

namespace SecurityAuditDashboard.Tests;

/// <summary>
/// Unit tests for ThreatDetectionService
/// Demonstrates: Complex mocking scenarios, testing business logic, edge cases
/// </summary>
public class ThreatDetectionServiceTests
{
    private readonly Mock<IThreatAlertRepository> _mockThreatAlertRepository;
    private readonly Mock<ILoginAttemptRepository> _mockLoginAttemptRepository;
    private readonly Mock<ISecurityEventRepository> _mockSecurityEventRepository;
    private readonly ThreatDetectionService _threatService;

    public ThreatDetectionServiceTests()
    {
        _mockThreatAlertRepository = new Mock<IThreatAlertRepository>();
        _mockLoginAttemptRepository = new Mock<ILoginAttemptRepository>();
        _mockSecurityEventRepository = new Mock<ISecurityEventRepository>();
        
        _threatService = new ThreatDetectionService(
            _mockThreatAlertRepository.Object,
            _mockLoginAttemptRepository.Object,
            _mockSecurityEventRepository.Object);
    }

    [Fact]
    public async Task AnalyzeLoginAttemptAsync_SuccessfulLogin_ShouldReturnFalse()
    {
        // Arrange
        var attempt = new LoginAttempt
        {
            UserId = "user123",
            Success = true,
            IpAddress = "192.168.1.1"
        };

        _mockLoginAttemptRepository
            .Setup(r => r.AddAsync(It.IsAny<LoginAttempt>()))
            .ReturnsAsync(attempt);

        // Act
        var result = await _threatService.AnalyzeLoginAttemptAsync(attempt);

        // Assert
        Assert.False(result);
        _mockLoginAttemptRepository.Verify(r => r.AddAsync(attempt), Times.Once);
    }

    [Fact]
    public async Task AnalyzeLoginAttemptAsync_FailedLogin_BelowThreshold_ShouldReturnFalse()
    {
        // Arrange
        var attempt = new LoginAttempt
        {
            UserId = "user123",
            Success = false,
            IpAddress = "192.168.1.1"
        };

        _mockLoginAttemptRepository
            .Setup(r => r.AddAsync(It.IsAny<LoginAttempt>()))
            .ReturnsAsync(attempt);

        _mockLoginAttemptRepository
            .Setup(r => r.GetFailedCountAsync(It.IsAny<string>(), It.IsAny<TimeSpan>()))
            .ReturnsAsync(3); // Below threshold of 5

        // Act
        var result = await _threatService.AnalyzeLoginAttemptAsync(attempt);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DetectBruteForceAsync_AboveThreshold_NoExistingAlert_ShouldCreateAlert()
    {
        // Arrange
        var userId = "user123";
        var ipAddress = "192.168.1.1";

        _mockLoginAttemptRepository
            .Setup(r => r.GetFailedCountAsync(userId, It.IsAny<TimeSpan>()))
            .ReturnsAsync(6); // Above threshold of 5

        _mockThreatAlertRepository
            .Setup(r => r.GetActiveAlertsAsync())
            .ReturnsAsync(new List<ThreatAlert>()); // No existing alerts

        ThreatAlert? capturedAlert = null;
        _mockThreatAlertRepository
            .Setup(r => r.AddAsync(It.IsAny<ThreatAlert>()))
            .Callback<ThreatAlert>(alert => capturedAlert = alert)
            .ReturnsAsync((ThreatAlert a) => a);

        // Act
        var result = await _threatService.DetectBruteForceAsync(userId, ipAddress);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(capturedAlert);
        Assert.Equal("Brute Force Attack", capturedAlert.ThreatType);
        Assert.Equal(ipAddress, capturedAlert.Source);
        Assert.Equal(EventSeverity.High, capturedAlert.Severity);
    }

    [Fact]
    public async Task DetectBruteForceAsync_ExistingAlert_ShouldNotCreateDuplicate()
    {
        // Arrange
        var userId = "user123";
        var ipAddress = "192.168.1.1";

        _mockLoginAttemptRepository
            .Setup(r => r.GetFailedCountAsync(userId, It.IsAny<TimeSpan>()))
            .ReturnsAsync(6);

        var existingAlert = new ThreatAlert
        {
            ThreatType = "Brute Force Attack",
            Source = ipAddress,
            Status = ThreatStatus.New
        };

        _mockThreatAlertRepository
            .Setup(r => r.GetActiveAlertsAsync())
            .ReturnsAsync(new List<ThreatAlert> { existingAlert });

        // Act
        var result = await _threatService.DetectBruteForceAsync(userId, ipAddress);

        // Assert
        Assert.Null(result);
        _mockThreatAlertRepository.Verify(r => r.AddAsync(It.IsAny<ThreatAlert>()), Times.Never);
    }

    [Fact]
    public async Task CreateThreatAlertAsync_ShouldCreateWithCorrectProperties()
    {
        // Arrange
        var threatType = "SQL Injection";
        var source = "web-form";
        var severity = EventSeverity.Critical;
        var description = "Potential SQL injection detected";

        ThreatAlert? capturedAlert = null;
        _mockThreatAlertRepository
            .Setup(r => r.AddAsync(It.IsAny<ThreatAlert>()))
            .Callback<ThreatAlert>(alert => capturedAlert = alert)
            .ReturnsAsync((ThreatAlert a) => a);

        // Act
        var result = await _threatService.CreateThreatAlertAsync(threatType, source, severity, description);

        // Assert
        Assert.NotNull(capturedAlert);
        Assert.Equal(threatType, capturedAlert.ThreatType);
        Assert.Equal(source, capturedAlert.Source);
        Assert.Equal(severity, capturedAlert.Severity);
        Assert.Equal(description, capturedAlert.Description);
        Assert.Equal(ThreatStatus.New, capturedAlert.Status);
    }

    [Fact]
    public async Task ResolveThreatAsync_ShouldUpdateThreatStatus()
    {
        // Arrange
        var threatId = 1;
        var resolvedBy = "admin";
        var resolutionNotes = "False positive - legitimate user";

        var threat = new ThreatAlert
        {
            Id = threatId,
            ThreatType = "Brute Force Attack",
            Status = ThreatStatus.New
        };

        _mockThreatAlertRepository
            .Setup(r => r.GetByIdAsync(threatId))
            .ReturnsAsync(threat);

        // Act
        await _threatService.ResolveThreatAsync(threatId, resolvedBy, resolutionNotes);

        // Assert
        Assert.Equal(ThreatStatus.Resolved, threat.Status);
        Assert.Equal(resolutionNotes, threat.ResolutionNotes);
        Assert.Equal(resolvedBy, threat.AssignedTo);
        Assert.NotNull(threat.ResolvedAt);
        
        _mockThreatAlertRepository.Verify(r => r.UpdateAsync(threat), Times.Once);
    }

    [Fact]
    public async Task GetActiveThreatsAsync_ShouldReturnActiveAlerts()
    {
        // Arrange
        var activeThreats = new List<ThreatAlert>
        {
            new() { Id = 1, ThreatType = "Alert1", Status = ThreatStatus.New },
            new() { Id = 2, ThreatType = "Alert2", Status = ThreatStatus.Investigating }
        };

        _mockThreatAlertRepository
            .Setup(r => r.GetActiveAlertsAsync())
            .ReturnsAsync(activeThreats);

        // Act
        var result = await _threatService.GetActiveThreatsAsync();

        // Assert
        Assert.Equal(2, result.Count());
    }
}
