using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;

namespace ModernWebGoat.Endpoints;

public static class A01_BrokenAccessControl
{
    public static void MapA01BrokenAccessControlEndpoints(this WebApplication app)
    {
        // VULNERABILITY A01: IDOR — any user can access any other user's full profile
        // No authentication or authorization check whatsoever
        app.MapGet("/api/users/{id:int}", async (int id, AppDbContext db) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user is null) return Results.NotFound(new { error = "User not found" });

            // VULNERABILITY A04: Returns SSN and credit card in plaintext
            return Results.Ok(new
            {
                user.Id,
                user.Username,
                user.Email,
                user.Role,
                user.SSN,
                user.CreditCard,
                user.ApiKey,
                user.FailedLoginAttempts
            });
        }).WithTags("A01 - Broken Access Control");

        // VULNERABILITY A01: Missing function-level authorization — no role check
        app.MapGet("/api/admin/users", async (AppDbContext db) =>
        {
            // Should require admin role but doesn't check at all
            var users = await db.Users.Select(u => new
            {
                u.Id,
                u.Username,
                u.Email,
                u.Role,
                u.SSN,
                u.CreditCard,
                u.ApiKey
            }).ToListAsync();

            return Results.Ok(users);
        }).WithTags("A01 - Broken Access Control");

        // VULNERABILITY A01: Path traversal — no sanitization of file name
        app.MapGet("/api/files/download", (string? name, IWebHostEnvironment env) =>
        {
            if (string.IsNullOrEmpty(name))
                return Results.BadRequest(new { error = "Provide a file name via ?name=" });

            // VULNERABLE: No path sanitization — allows ../../etc/passwd
            var filePath = Path.Combine(env.WebRootPath, "uploads", name);

            if (!File.Exists(filePath))
                return Results.NotFound(new { error = "File not found", path = filePath });

            return Results.File(filePath, "application/octet-stream", Path.GetFileName(name));
        }).WithTags("A01 - Broken Access Control");

        // VULNERABILITY A01: SSRF — Unvalidated URL fetch (consolidated from OWASP 2021 A10)
        var fetchGroup = app.MapGroup("/api/fetch").WithTags("A01 - Broken Access Control (SSRF)");

        fetchGroup.MapGet("/", async (string? url, IHttpClientFactory httpClientFactory) =>
        {
            if (string.IsNullOrEmpty(url))
                return Results.BadRequest(new { error = "Provide a URL via ?url=" });

            try
            {
                // VULNERABLE: No URL validation — can access internal services,
                // cloud metadata endpoints (169.254.169.254), localhost, etc.
                var client = httpClientFactory.CreateClient();
                var response = await client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                return Results.Ok(new
                {
                    requestedUrl = url,
                    statusCode = (int)response.StatusCode,
                    contentLength = content.Length,
                    content = content.Length > 5000 ? content[..5000] + "... (truncated)" : content,
                    vulnerability = "No URL validation — attacker can access internal services, cloud metadata, etc."
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new
                {
                    requestedUrl = url,
                    error = ex.Message
                });
            }
        });

        // VULNERABILITY A01: SSRF — POST version for form submissions
        fetchGroup.MapPost("/", async (FetchRequest request, IHttpClientFactory httpClientFactory) =>
        {
            if (string.IsNullOrEmpty(request.Url))
                return Results.BadRequest(new { error = "Provide a URL" });

            try
            {
                var client = httpClientFactory.CreateClient();
                var response = await client.GetAsync(request.Url);
                var content = await response.Content.ReadAsStringAsync();

                return Results.Ok(new
                {
                    requestedUrl = request.Url,
                    statusCode = (int)response.StatusCode,
                    content = content.Length > 5000 ? content[..5000] + "... (truncated)" : content
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
    }

    private record FetchRequest(string Url);
}
