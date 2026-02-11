using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;

namespace ModernWebGoat.Endpoints;

public static class A05_Injection
{
    public static void MapA05InjectionEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/injection").WithTags("A05 - Injection");

        // VULNERABILITY A05: SQL Injection via string concatenation
        group.MapGet("/products", (string? q, IConfiguration config) =>
        {
            if (string.IsNullOrEmpty(q))
                return Results.BadRequest(new { error = "Provide a search query via ?q=" });

            var connectionString = config.GetConnectionString("DefaultConnection");
            using var connection = new SqliteConnection(connectionString);
            connection.Open();

            // VULNERABLE: Direct string concatenation in SQL query
            var sql = $"SELECT Id, Name, Description, Price, Stock FROM Products WHERE Name LIKE '%{q}%'";
            using var command = new SqliteCommand(sql, connection);
            using var reader = command.ExecuteReader();

            var products = new List<object>();
            while (reader.Read())
            {
                products.Add(new
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Description = reader.GetString(2),
                    Price = reader.GetDecimal(3),
                    Stock = reader.GetInt32(4)
                });
            }

            return Results.Ok(new { query = q, sql, results = products });
        });

        // VULNERABILITY A05: Command Injection
        group.MapPost("/exec", (CommandRequest request) =>
        {
            if (string.IsNullOrEmpty(request.Host))
                return Results.BadRequest(new { error = "Provide a host to ping" });

            // VULNERABLE: User input passed directly to shell command
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "/bin/sh",
                    Arguments = $"-c \"ping -c 2 {request.Host}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            return Results.Ok(new { command = $"ping -c 2 {request.Host}", output, error });
        });

        // VULNERABILITY A05: Stored XSS — comments stored and rendered as raw HTML
        group.MapGet("/comments", async (AppDbContext db) =>
        {
            var comments = await db.Comments
                .OrderByDescending(c => c.CreatedAt)
                .Select(c => new { c.Id, c.Username, c.Content, c.CreatedAt })
                .ToListAsync();

            return Results.Ok(comments);
        });

        group.MapPost("/comments", async (CommentRequest request, AppDbContext db) =>
        {
            // VULNERABLE: No HTML sanitization — content stored as-is
            var comment = new Models.Comment
            {
                UserId = request.UserId,
                Username = request.Username,
                Content = request.Content, // Raw HTML!
                CreatedAt = DateTime.UtcNow
            };

            db.Comments.Add(comment);
            await db.SaveChangesAsync();

            return Results.Created($"/api/injection/comments", new { comment.Id, comment.Username, comment.Content });
        });
    }

    private record CommandRequest(string Host);
    private record CommentRequest(int UserId, string Username, string Content);
}
