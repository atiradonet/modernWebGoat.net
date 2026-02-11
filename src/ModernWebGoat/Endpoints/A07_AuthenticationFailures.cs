using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ModernWebGoat.Data;

namespace ModernWebGoat.Endpoints;

public static class A07_AuthenticationFailures
{
    private static string Md5Hash(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }

    public static void MapA07AuthenticationFailuresEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth").WithTags("A07 - Authentication Failures");

        // VULNERABILITY A07: No rate limiting, no account lockout, weak JWT
        group.MapPost("/login", async (LoginRequest request, AppDbContext db, IConfiguration config) =>
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
                return Results.BadRequest(new { error = "Username and password are required" });

            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
                return Results.Unauthorized();

            var hash = Md5Hash(request.Password);
            if (user.PasswordHash != hash)
            {
                // VULNERABILITY A06/A07: Tracked but never enforced
                user.FailedLoginAttempts++;
                await db.SaveChangesAsync();

                // VULNERABILITY A09: Failed login not logged
                return Results.Unauthorized();
            }

            // Reset failed attempts on success (but still no lockout)
            user.FailedLoginAttempts = 0;
            await db.SaveChangesAsync();

            // VULNERABILITY A07: Weak JWT — 5-char key, no expiration
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],
                audience: config["Jwt:Audience"],
                claims: new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("userId", user.Id.ToString())
                },
                // VULNERABILITY A07: No expiration set
                signingCredentials: creds
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // VULNERABILITY A07: Token reuse — same token returned, no rotation
            return Results.Ok(new { token = tokenString, user.Username, user.Role });
        });

        // VULNERABILITY A07: No password complexity requirements
        group.MapPost("/register", async (RegisterRequest request, AppDbContext db) =>
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
                return Results.BadRequest(new { error = "Username and password are required" });

            // VULNERABILITY A07: No minimum length, no complexity requirements
            // Even a single character password is accepted

            if (await db.Users.AnyAsync(u => u.Username == request.Username))
                return Results.Conflict(new { error = "Username already exists" });

            var user = new Models.User
            {
                Username = request.Username,
                PasswordHash = Md5Hash(request.Password), // A04: MD5
                Email = request.Email ?? "",
                Role = "user",
                SSN = "",
                CreditCard = "",
                ApiKey = $"sk-{request.Username}-{Guid.NewGuid()}"
            };

            db.Users.Add(user);
            await db.SaveChangesAsync();

            return Results.Created($"/api/users/{user.Id}", new { user.Id, user.Username, user.Role });
        });

        // Info endpoint: show current JWT config (for learning)
        group.MapGet("/jwt-info", (IConfiguration config) =>
        {
            return Results.Ok(new
            {
                signingKey = config["Jwt:Key"],
                signingKeyLength = config["Jwt:Key"]?.Length,
                algorithm = "HS256",
                expirationValidated = false,
                lifetimeValidated = false,
                notes = new[]
                {
                    "Signing key is only 5 characters — trivially brute-forceable",
                    "Token expiration is not validated (ValidateLifetime = false)",
                    "No refresh token rotation implemented",
                    "JWT secret is hardcoded in appsettings.json"
                }
            });
        });
    }

    private record LoginRequest(string Username, string Password);
    private record RegisterRequest(string Username, string Password, string? Email);
}
