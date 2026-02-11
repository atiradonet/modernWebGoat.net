using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;
using ModernWebGoat.Models;

namespace ModernWebGoat.Endpoints;

public static class A09_LoggingFailures
{
    public static void MapA09LoggingFailuresEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/log").WithTags("A09 - Security Logging and Alerting Failures");

        // VULNERABILITY A09: Logs sensitive data to console
        group.MapPost("/sensitive", async (SensitiveDataRequest request, AppDbContext db, ILogger<Program> logger) =>
        {
            // VULNERABLE: Logging passwords and credit card numbers
            logger.LogInformation("User login attempt - Username: {Username}, Password: {Password}",
                request.Username, request.Password);

            logger.LogInformation("Payment processed - Card: {CreditCard}, CVV: {CVV}, Amount: {Amount}",
                request.CreditCard, request.CVV, request.Amount);

            // Also persist to database audit log with sensitive data
            var auditLog = new AuditLog
            {
                Action = "SensitiveDataLogged",
                Details = $"Username: {request.Username}, Password: {request.Password}, " +
                          $"CreditCard: {request.CreditCard}, CVV: {request.CVV}",
                Timestamp = DateTime.UtcNow
            };

            db.AuditLogs.Add(auditLog);
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                message = "Sensitive data has been logged to console and database",
                logged = new
                {
                    username = request.Username,
                    password = "***LOGGED IN PLAINTEXT TO CONSOLE***",
                    creditCard = "***LOGGED IN PLAINTEXT TO CONSOLE***",
                    cvv = "***LOGGED IN PLAINTEXT TO CONSOLE***"
                },
                vulnerability = new[]
                {
                    "Passwords logged in plaintext",
                    "Credit card numbers logged in plaintext",
                    "CVV logged in plaintext",
                    "Sensitive data persisted to audit log without masking",
                    "No log access controls"
                }
            });
        });

        // Show audit logs (including sensitive data)
        group.MapGet("/audit", async (AppDbContext db) =>
        {
            var logs = await db.AuditLogs
                .OrderByDescending(l => l.Timestamp)
                .Take(50)
                .Select(l => new { l.Id, l.Action, l.Details, l.Timestamp })
                .ToListAsync();

            return Results.Ok(new
            {
                note = "Audit logs contain sensitive data in plaintext — a monitoring failure",
                logs
            });
        });
    }

    private record SensitiveDataRequest(
        string? Username,
        string? Password,
        string? CreditCard,
        string? CVV,
        decimal? Amount);
}
