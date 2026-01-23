using Microsoft.AspNetCore.SignalR;
using SecurityAuditDashboard.Core.Entities;

namespace SecurityAuditDashboard.Web.Hubs;

/// <summary>
/// SignalR hub for real-time security notifications
/// </summary>
public class SecurityHub : Hub
{
    public override async Task OnConnectedAsync()
    {
        // Add user to their role group for targeted notifications
        if (Context.User?.Identity?.IsAuthenticated == true)
        {
            var userId = Context.UserIdentifier;
            if (!string.IsNullOrEmpty(userId))
            {
                await Groups.AddToGroupAsync(Context.ConnectionId, $"user_{userId}");
            }

            // Add to role-based groups
            if (Context.User.IsInRole("Admin"))
            {
                await Groups.AddToGroupAsync(Context.ConnectionId, "Admins");
            }
            if (Context.User.IsInRole("Analyst"))
            {
                await Groups.AddToGroupAsync(Context.ConnectionId, "Analysts");
            }
        }

        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await base.OnDisconnectedAsync(exception);
    }

    /// <summary>
    /// Subscribe to security alerts
    /// </summary>
    public async Task SubscribeToAlerts()
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, "AlertSubscribers");
    }

    /// <summary>
    /// Unsubscribe from security alerts
    /// </summary>
    public async Task UnsubscribeFromAlerts()
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, "AlertSubscribers");
    }
}
