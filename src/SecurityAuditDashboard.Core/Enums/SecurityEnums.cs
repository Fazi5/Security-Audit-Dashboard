namespace SecurityAuditDashboard.Core.Enums;

/// <summary>
/// Represents the severity level of a security event
/// </summary>
public enum EventSeverity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// Represents the type of security event
/// </summary>
public enum EventType
{
    LoginSuccess,
    LoginFailure,
    LogoutSuccess,
    PasswordChange,
    PasswordReset,
    AccountLockout,
    UnauthorizedAccess,
    SuspiciousActivity,
    DataExport,
    ConfigurationChange,
    UserCreated,
    UserDeleted,
    RoleChanged,
    TwoFactorEnabled,
    TwoFactorDisabled
}

/// <summary>
/// Represents the status of a threat alert
/// </summary>
public enum ThreatStatus
{
    New,
    Investigating,
    Resolved,
    FalsePositive,
    Escalated
}

/// <summary>
/// Represents user roles in the system
/// </summary>
public enum UserRole
{
    Viewer,
    Analyst,
    Admin
}
