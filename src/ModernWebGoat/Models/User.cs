namespace ModernWebGoat.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;

    // VULNERABILITY A04: Passwords stored as MD5 hex strings — no salt, trivially crackable
    public string PasswordHash { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = "user"; // "user" or "admin"

    // VULNERABILITY A04: Sensitive data stored in plaintext, returned by API
    public string SSN { get; set; } = string.Empty;
    public string CreditCard { get; set; } = string.Empty;

    public string ApiKey { get; set; } = string.Empty;

    // VULNERABILITY A06: Predictable reset token = MD5(username + ticks)
    public string? PasswordResetToken { get; set; }

    // VULNERABILITY A07: Tracked but never enforced — no lockout
    public int FailedLoginAttempts { get; set; }
}
