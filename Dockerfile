# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and project files
COPY SecurityAuditDashboard.sln .
COPY src/SecurityAuditDashboard.Core/SecurityAuditDashboard.Core.csproj src/SecurityAuditDashboard.Core/
COPY src/SecurityAuditDashboard.Shared/SecurityAuditDashboard.Shared.csproj src/SecurityAuditDashboard.Shared/
COPY src/SecurityAuditDashboard.Infrastructure/SecurityAuditDashboard.Infrastructure.csproj src/SecurityAuditDashboard.Infrastructure/
COPY src/SecurityAuditDashboard.Web/SecurityAuditDashboard.Web.csproj src/SecurityAuditDashboard.Web/
COPY tests/SecurityAuditDashboard.Tests/SecurityAuditDashboard.Tests.csproj tests/SecurityAuditDashboard.Tests/

# Restore dependencies
RUN dotnet restore

# Copy source code
COPY . .

# Build application
RUN dotnet build -c Release --no-restore

# Run tests
RUN dotnet test -c Release --no-build --verbosity normal

# Publish application
RUN dotnet publish src/SecurityAuditDashboard.Web/SecurityAuditDashboard.Web.csproj -c Release -o /app/publish --no-build

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Create non-root user for security
RUN adduser --disabled-password --gecos "" appuser

# Copy published files
COPY --from=build /app/publish .

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DOTNET_RUNNING_IN_CONTAINER=true

# Entry point
ENTRYPOINT ["dotnet", "SecurityAuditDashboard.Web.dll"]
