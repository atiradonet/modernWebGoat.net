using System.Security.Cryptography;
using System.Text;
using ModernWebGoat.Models;

namespace ModernWebGoat.Data;

public static class SeedData
{
    // VULNERABILITY A04: MD5 hashing with no salt
    private static string Md5Hash(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }

    public static void Initialize(AppDbContext db)
    {
        db.Database.EnsureCreated();

        if (db.Users.Any()) return;

        // Seed users — passwords are trivially weak (A07) and hashed with MD5 (A04)
        db.Users.AddRange(
            new User
            {
                Username = "admin",
                PasswordHash = Md5Hash("admin123"),
                Email = "admin@modernwebgoat.local",
                Role = "admin",
                SSN = "123-45-6789",
                CreditCard = "4111-1111-1111-1111",
                ApiKey = "sk-admin-00000000-0000-0000-0000-000000000000"
            },
            new User
            {
                Username = "alice",
                PasswordHash = Md5Hash("password"),
                Email = "alice@example.com",
                Role = "user",
                SSN = "987-65-4321",
                CreditCard = "5500-0000-0000-0004",
                ApiKey = "sk-alice-11111111-1111-1111-1111-111111111111"
            },
            new User
            {
                Username = "bob",
                PasswordHash = Md5Hash("bob"),
                Email = "bob@example.com",
                Role = "user",
                SSN = "555-12-3456",
                CreditCard = "3400-0000-0000-009",
                ApiKey = "sk-bob-22222222-2222-2222-2222-222222222222"
            }
        );

        // Seed products
        db.Products.AddRange(
            new Product { Name = "Laptop", Description = "High-performance laptop", Price = 999.99m, Stock = 50 },
            new Product { Name = "Phone", Description = "Latest smartphone", Price = 699.99m, Stock = 100 },
            new Product { Name = "Headphones", Description = "Noise-cancelling headphones", Price = 199.99m, Stock = 200 },
            new Product { Name = "Keyboard", Description = "Mechanical keyboard", Price = 149.99m, Stock = 75 },
            new Product { Name = "Monitor", Description = "4K Ultra HD monitor", Price = 449.99m, Stock = 30 }
        );

        // Seed comments — includes stored XSS payload (A05)
        db.Comments.AddRange(
            new Comment
            {
                UserId = 1,
                Username = "admin",
                Content = "Welcome to ModernWebGoat! This is a safe comment.",
                CreatedAt = DateTime.UtcNow.AddDays(-2)
            },
            new Comment
            {
                UserId = 2,
                Username = "alice",
                Content = "<script>alert('XSS from stored comment!')</script>This comment has a surprise.",
                CreatedAt = DateTime.UtcNow.AddDays(-1)
            },
            new Comment
            {
                UserId = 3,
                Username = "bob",
                Content = "Just a normal comment from Bob.",
                CreatedAt = DateTime.UtcNow
            }
        );

        db.SaveChanges();
    }
}
