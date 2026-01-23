namespace SecurityAuditDashboard.Shared.DTOs;

/// <summary>
/// DTO for user registration
/// </summary>
public record RegisterDto(
    string Email,
    string Password,
    string FirstName,
    string LastName
);

/// <summary>
/// DTO for user login
/// </summary>
public record LoginDto(
    string Email,
    string Password,
    bool RememberMe = false
);

/// <summary>
/// DTO for authentication response
/// </summary>
public record AuthResponseDto(
    bool Success,
    string? Token,
    string? Message,
    UserDto? User
);

/// <summary>
/// DTO for user information
/// </summary>
public record UserDto(
    string Id,
    string Email,
    string FirstName,
    string LastName,
    string Role,
    DateTime CreatedAt,
    DateTime? LastLoginAt,
    bool IsActive
);

/// <summary>
/// DTO for audit log display
/// </summary>
public record AuditLogDto(
    int Id,
    string UserId,
    string UserName,
    string Action,
    string? Details,
    string IpAddress,
    DateTime Timestamp,
    bool IsSuccessful
);

/// <summary>
/// DTO for security event display
/// </summary>
public record SecurityEventDto(
    int Id,
    string EventType,
    string Severity,
    string Description,
    string? Source,
    string? UserId,
    DateTime Timestamp,
    bool IsResolved,
    string? ResolvedBy
);

/// <summary>
/// DTO for threat alert display
/// </summary>
public record ThreatAlertDto(
    int Id,
    string ThreatType,
    string Source,
    string Severity,
    string Description,
    string Status,
    DateTime DetectedAt,
    string? AssignedTo,
    DateTime? ResolvedAt
);

/// <summary>
/// DTO for dashboard statistics
/// </summary>
public record DashboardStatsDto(
    int TotalEvents,
    int CriticalEvents,
    int FailedLogins,
    int ActiveThreats,
    int ResolvedThreats,
    DateTime LastScanTime,
    List<EventsByDayDto> EventsByDay,
    List<EventsBySeverityDto> EventsBySeverity
);

/// <summary>
/// DTO for events grouped by day
/// </summary>
public record EventsByDayDto(string Date, int Count);

/// <summary>
/// DTO for events grouped by severity
/// </summary>
public record EventsBySeverityDto(string Severity, int Count);

/// <summary>
/// DTO for resolving a threat
/// </summary>
public record ResolveThreatDto(
    int ThreatId,
    string ResolutionNotes
);
