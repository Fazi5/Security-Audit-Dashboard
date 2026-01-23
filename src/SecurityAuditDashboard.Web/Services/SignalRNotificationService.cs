using Microsoft.AspNetCore.SignalR;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Interfaces;
using SecurityAuditDashboard.Web.Hubs;

namespace SecurityAuditDashboard.Web.Services;

/// <summary>
/// SignalR-based notification service for real-time alerts
/// </summary>
public class SignalRNotificationService : INotificationService
{
    private readonly IHubContext<SecurityHub> _hubContext;

    public SignalRNotificationService(IHubContext<SecurityHub> hubContext)
    {
        _hubContext = hubContext;
    }

    public async Task NotifySecurityEventAsync(SecurityEvent securityEvent)
    {
        var notification = new
        {
            Type = "SecurityEvent",
            Event = new
            {
                securityEvent.Id,
                EventType = securityEvent.EventType.ToString(),
                Severity = securityEvent.Severity.ToString(),
                securityEvent.Description,
                securityEvent.Timestamp
            }
        };

        // Notify all admins and analysts
        await _hubContext.Clients.Group("Admins").SendAsync("ReceiveSecurityEvent", notification);
        await _hubContext.Clients.Group("Analysts").SendAsync("ReceiveSecurityEvent", notification);
        
        // Notify alert subscribers
        await _hubContext.Clients.Group("AlertSubscribers").SendAsync("ReceiveSecurityEvent", notification);
    }

    public async Task NotifyThreatAlertAsync(ThreatAlert threat)
    {
        var notification = new
        {
            Type = "ThreatAlert",
            Alert = new
            {
                threat.Id,
                threat.ThreatType,
                threat.Source,
                Severity = threat.Severity.ToString(),
                threat.Description,
                Status = threat.Status.ToString(),
                threat.DetectedAt
            }
        };

        // Notify all admins immediately for threat alerts
        await _hubContext.Clients.Group("Admins").SendAsync("ReceiveThreatAlert", notification);
        await _hubContext.Clients.Group("Analysts").SendAsync("ReceiveThreatAlert", notification);
        
        // Notify alert subscribers
        await _hubContext.Clients.Group("AlertSubscribers").SendAsync("ReceiveThreatAlert", notification);
    }
}
