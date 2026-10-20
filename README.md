# Security Audit Dashboard

A comprehensive .NET 9 Blazor Server application for security monitoring, audit logging, and threat detection. Built with a layered Clean Architecture (Core, Infrastructure, Web, Shared), real-time alerts over SignalR, and Docker deployment.

## 🚀 Features

- **Dashboard** - Real-time security metrics and KPIs
- **Security Events** - Track and resolve security incidents
- **Audit Logs** - Complete activity logging with search
- **Threat Alerts** - Detect and respond to security threats
- **User Management** - Role-based access control (Admin, Analyst, Viewer)
- **Real-time Updates** - SignalR-powered live notifications

## 🏗️ Architecture

```
SecurityAuditDashboard/
├── src/
│   ├── SecurityAuditDashboard.Web/           # Blazor Server App
│   ├── SecurityAuditDashboard.Core/          # Domain & Interfaces
│   ├── SecurityAuditDashboard.Infrastructure/ # Data & Services
│   └── SecurityAuditDashboard.Shared/        # DTOs
└── tests/
    └── SecurityAuditDashboard.Tests/         # Unit Tests
```

## 🛠️ Technologies & Concepts

| Concept | Implementation |
|---------|----------------|
| **Dependency Injection** | Service registration with scoped/singleton lifetimes |
| **Entity Framework Core** | Code-first with SQLite, migrations |
| **ASP.NET Core Identity** | Authentication, authorization, password hashing |
| **Blazor Server** | Interactive components, state management |
| **SignalR** | Real-time security alerts |
| **Repository Pattern** | Data access abstraction |
| **Clean Architecture** | Separation of concerns |

## 📋 Prerequisites

- .NET 9 SDK
- Visual Studio 2022 or VS Code

## 🚀 Getting Started

1. **Clone the repository**
   ```bash
   cd c:\Users\faiza\OneDrive\Desktop\dotnet\SecurityAuditDashboard
   ```

2. **Build the solution**
   ```bash
   dotnet build
   ```

3. **Run the application**
   ```bash
   dotnet run --project src/SecurityAuditDashboard.Web
   ```

4. **Open in browser**
   Navigate to `https://localhost:5001`

## 🔐 Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@securitydashboard.com | Admin@123! |

## 📊 Key .NET Concepts Demonstrated

### 1. Dependency Injection
- Scoped services for database operations
- Singleton for SignalR hub context
- Interface-based registration

### 2. Entity Framework Core
- Code-first approach
- Fluent API configuration
- Indexes for performance
- SQLite for simplicity

### 3. ASP.NET Core Identity
- Custom ApplicationUser
- Role-based authorization
- Password policies
- Account lockout

### 4. Blazor Components
- Component lifecycle
- State management
- Event handling
- Two-way binding

### 5. SignalR Real-time
- Hub implementation
- Group-based notifications
- Client-server messaging

## 🎯 Interview Discussion Points

1. **Why SQLite?** - Simplicity for demo, easily swappable with SQL Server
2. **Scoped vs Singleton** - DbContext is scoped, SignalR hub context is singleton
3. **Repository Pattern** - Abstraction for testing and flexibility
4. **Clean Architecture** - Core has no dependencies on Infrastructure

## 🌟 Industry Standard Improvements

### 1. Structured Logging (Serilog)
- **Console & File Sinks**: Logs to console for dev, rolling files for prod
- **Enrichment**: Request ID, machine name, thread ID, and user details
- **Request Logging**: Performance metrics for every HTTP request

### 2. Containerization (Docker)
- **Multi-stage Build**: Optimized Dockerfile for small image size
- **Docker Compose**: Orchestrates app with persistent volumes
- **Health Checks**: Built-in endpoints for container orchestration

### 3. Two-Factor Authentication (2FA)
- **TOTP Standards**: Compatible with Google/Microsoft Authenticator
- **Security**: Base32 secret generation, HMAC-SHA1 validation
- **QR Code**: Auto-generated setup for easy user onboarding

## 🐳 Running with Docker

```bash
docker-compose up -d --build
```
Access at: **http://localhost:5000**

## 📝 License

MIT License
