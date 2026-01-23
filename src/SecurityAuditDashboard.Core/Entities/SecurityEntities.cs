using SecurityAuditDashboard.Core.Enums;

namespace SecurityAuditDashboard.Core.Entities;

/// <summary>
/// Represents an audit log entry tracking user activities
/// </summary>
public class AuditLog
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? Details { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string? UserAgent { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public bool IsSuccessful { get; set; } = true;
}

/// <summary>
/// Represents a security event in the system
/// </summary>
public class SecurityEvent
{
    public int Id { get; set; }
    public EventType EventType { get; set; }
    public EventSeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public string? Source { get; set; }
    public string? UserId { get; set; }
    public string? IpAddress { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public bool IsResolved { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public string? ResolvedBy { get; set; }
    public string? Resolution { get; set; }
}

/// <summary>
/// Represents a login attempt (successful or failed)
/// </summary>
public class LoginAttempt
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string? UserAgent { get; set; }
    public string? FailureReason { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? Location { get; set; }
}

/// <summary>
/// Represents a detected threat alert
/// </summary>
public class ThreatAlert
{
    public int Id { get; set; }
    public string ThreatType { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public EventSeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public ThreatStatus Status { get; set; } = ThreatStatus.New;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public string? AssignedTo { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public string? ResolutionNotes { get; set; }
}
