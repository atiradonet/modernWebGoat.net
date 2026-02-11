namespace ModernWebGoat.Models;

public class Comment
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;

    // VULNERABILITY A03: Raw HTML stored and rendered with @Html.Raw — stored XSS
    public string Content { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
