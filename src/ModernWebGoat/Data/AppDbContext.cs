using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Models;

namespace ModernWebGoat.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Product> Products => Set<Product>();
    public DbSet<Order> Orders => Set<Order>();
    public DbSet<Comment> Comments => Set<Comment>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
}
