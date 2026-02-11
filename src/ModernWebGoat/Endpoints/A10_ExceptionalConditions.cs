using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;

namespace ModernWebGoat.Endpoints;

public static class A10_ExceptionalConditions
{
    // Simulated account balances (in-memory for demo)
    private static readonly Dictionary<string, decimal> Accounts = new()
    {
        ["alice"] = 1000.00m,
        ["bob"] = 500.00m,
        ["admin"] = 9999.99m
    };

    private static readonly object BalanceLock = new();

    public static void MapA10ExceptionalConditionsEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/exceptional").WithTags("A10 - Mishandling of Exceptional Conditions");

        // VULNERABILITY A10: Exception in auth causes fail-open access
        group.MapGet("/fail-open", (string? token) =>
        {
            bool isAuthenticated;
            try
            {
                // VULNERABLE: If token parsing throws, we default to authenticated = true (fail open)
                if (string.IsNullOrEmpty(token))
                    throw new ArgumentNullException(nameof(token));

                // Simulate token validation that can throw on malformed input
                if (token.Length < 10)
                    throw new FormatException("Token too short");

                isAuthenticated = token.StartsWith("valid-");
            }
            catch
            {
                // VULNERABLE: Fail-open — exception defaults to granting access
                isAuthenticated = true;
            }

            if (isAuthenticated)
            {
                return Results.Ok(new
                {
                    access = "GRANTED",
                    secretData = "This is sensitive data that should require authentication",
                    vulnerability = "Exception during authentication caused fail-open. " +
                        "The catch block defaults isAuthenticated to true instead of false."
                });
            }

            return Results.Json(new { access = "DENIED" }, statusCode: 403);
        });

        // VULNERABILITY A10: NullReferenceException leaks stack trace
        group.MapGet("/null-deref", async (int? id, AppDbContext db) =>
        {
            // VULNERABLE: No null check — accessing a non-existent record causes NullReferenceException
            // The stack trace is exposed via DeveloperExceptionPage (A02)
            var user = await db.Users.FindAsync(id ?? 99999);

            // This will throw NullReferenceException if user is null
            return Results.Ok(new
            {
                username = user!.Username,
                email = user.Email,
                vulnerability = "No null check on database result — NullReferenceException leaks stack trace"
            });
        });

        // VULNERABILITY A10: Integer overflow — no checked arithmetic
        group.MapGet("/overflow", (int? price, int? quantity) =>
        {
            var p = price ?? 2147483647; // int.MaxValue
            var q = quantity ?? 2;

            // VULNERABLE: Unchecked integer multiplication can overflow silently
            var total = p * q; // Wraps around to negative!

            return Results.Ok(new
            {
                price = p,
                quantity = q,
                total,
                overflowed = total < 0 || (p > 0 && q > 0 && total < p),
                vulnerability = "Integer overflow: int.MaxValue * 2 wraps to a negative number. " +
                    "This could allow purchasing items for negative prices or bypassing balance checks."
            });
        });

        // VULNERABILITY A10: Transfer with no validation for edge cases
        group.MapPost("/transfer", (TransferRequest request) =>
        {
            if (string.IsNullOrEmpty(request.From) || string.IsNullOrEmpty(request.To))
                return Results.BadRequest(new { error = "Provide 'from' and 'to' account names" });

            lock (BalanceLock)
            {
                if (!Accounts.ContainsKey(request.From))
                    return Results.NotFound(new { error = $"Account '{request.From}' not found" });
                if (!Accounts.ContainsKey(request.To))
                    return Results.NotFound(new { error = $"Account '{request.To}' not found" });

                // VULNERABLE: No validation for negative amounts, self-transfers, or zero amounts
                // Negative amount reverses the transfer direction
                Accounts[request.From] -= request.Amount;
                Accounts[request.To] += request.Amount;

                return Results.Ok(new
                {
                    from = new { account = request.From, balance = Accounts[request.From] },
                    to = new { account = request.To, balance = Accounts[request.To] },
                    transferred = request.Amount,
                    vulnerability = "No validation for negative amounts (reverses transfer), " +
                        "self-transfers, zero amounts, or amounts exceeding balance."
                });
            }
        });

        // VULNERABILITY A10: TOCTOU race condition on withdrawal
        group.MapPost("/withdraw", async (WithdrawRequest request) =>
        {
            if (string.IsNullOrEmpty(request.Account))
                return Results.BadRequest(new { error = "Provide an account name" });

            if (!Accounts.ContainsKey(request.Account))
                return Results.NotFound(new { error = $"Account '{request.Account}' not found" });

            // VULNERABLE: TOCTOU — check and update are not atomic
            // Multiple concurrent requests can all pass the balance check before any deduction
            var balance = Accounts[request.Account];

            if (balance < request.Amount)
                return Results.BadRequest(new
                {
                    error = "Insufficient funds",
                    balance,
                    requested = request.Amount
                });

            // Simulate processing delay that widens the TOCTOU window
            await Task.Delay(100);

            Accounts[request.Account] -= request.Amount;

            return Results.Ok(new
            {
                account = request.Account,
                withdrawn = request.Amount,
                previousBalance = balance,
                newBalance = Accounts[request.Account],
                vulnerability = "TOCTOU race condition: balance check and deduction are not atomic. " +
                    "Send multiple concurrent requests to withdraw more than the balance allows."
            });
        });

        // Info endpoint: category overview
        group.MapGet("/info", () =>
        {
            return Results.Ok(new
            {
                category = "A10:2025 — Mishandling of Exceptional Conditions",
                description = "This category covers failures in handling edge cases, error conditions, " +
                    "and exceptional situations that lead to security vulnerabilities.",
                vulnerabilities = new[]
                {
                    new { endpoint = "GET /api/exceptional/fail-open?token=", description = "Exception in auth causes fail-open access grant" },
                    new { endpoint = "GET /api/exceptional/null-deref?id=99999", description = "NullReferenceException leaks stack trace" },
                    new { endpoint = "GET /api/exceptional/overflow?price=2147483647&quantity=2", description = "Integer overflow wraps to negative" },
                    new { endpoint = "POST /api/exceptional/transfer", description = "No validation for negative amounts or self-transfers" },
                    new { endpoint = "POST /api/exceptional/withdraw", description = "TOCTOU race condition allows overdraft" }
                }
            });
        });
    }

    private record TransferRequest(string From, string To, decimal Amount);
    private record WithdrawRequest(string Account, decimal Amount);
}
