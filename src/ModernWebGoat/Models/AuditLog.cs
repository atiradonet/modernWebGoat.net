namespace ModernWebGoat.Models;

public class AuditLog
{
    public int Id { get; set; }
    public string Action { get; set; } = string.Empty;

    // VULNERABILITY A09: Logs may contain sensitive data (passwords, credit cards)
    public string Details { get; set; } = string.Empty;

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
