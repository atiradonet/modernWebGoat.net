using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;
using ModernWebGoat.Models;

namespace ModernWebGoat.Endpoints;

public static class A04_InsecureDesign
{
    private static string Md5Hash(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }

    public static void MapA04InsecureDesignEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api").WithTags("A04 - Insecure Design");

        // VULNERABILITY A04: Negative quantity allows credit — business logic flaw
        // VULNERABILITY A04: Coupon can be reused unlimited times
        group.MapPost("/orders", async (OrderRequest request, AppDbContext db) =>
        {
            var product = await db.Products.FindAsync(request.ProductId);
            if (product is null)
                return Results.NotFound(new { error = "Product not found" });

            // VULNERABLE: No validation that quantity is positive
            // Negative quantity results in negative total = credit to user
            var discount = 0m;
            if (!string.IsNullOrEmpty(request.CouponCode))
            {
                // VULNERABLE: Any non-empty coupon gives 50% off, reusable unlimited times
                if (request.CouponCode == "DISCOUNT50")
                    discount = 0.5m;
            }

            var total = product.Price * request.Quantity * (1 - discount);

            var order = new Order
            {
                UserId = request.UserId,
                ProductId = request.ProductId,
                Quantity = request.Quantity, // Can be negative!
                TotalPrice = total,
                CouponCode = request.CouponCode,
                OrderDate = DateTime.UtcNow
            };

            db.Orders.Add(order);
            await db.SaveChangesAsync();

            return Results.Created($"/api/orders/{order.Id}", new
            {
                order.Id,
                product = product.Name,
                order.Quantity,
                unitPrice = product.Price,
                discount = $"{discount:P0}",
                order.TotalPrice,
                order.CouponCode,
                warning = total < 0 ? "Negative total — user receives credit!" : null
            });
        });

        // VULNERABILITY A04: Predictable password reset token
        group.MapPost("/password-reset", async (string username, AppDbContext db) =>
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user is null)
                // VULNERABILITY: Reveals whether username exists
                return Results.NotFound(new { error = $"User '{username}' not found" });

            // VULNERABLE: Token = MD5(username + DateTime.Now.Ticks) — predictable
            var token = Md5Hash($"{username}{DateTime.Now.Ticks}");
            user.PasswordResetToken = token;
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                message = "Password reset token generated",
                token, // VULNERABLE: Token returned directly in response
                vulnerability = "Token is MD5(username + ticks) — predictable if attacker knows approximate time"
            });
        });

        // List orders (no auth check)
        group.MapGet("/orders", async (AppDbContext db) =>
        {
            var orders = await db.Orders
                .OrderByDescending(o => o.OrderDate)
                .Select(o => new
                {
                    o.Id, o.UserId, o.ProductId, o.Quantity,
                    o.TotalPrice, o.OrderDate, o.CouponCode
                })
                .ToListAsync();

            return Results.Ok(orders);
        });
    }

    private record OrderRequest(int UserId, int ProductId, int Quantity, string? CouponCode);
}
