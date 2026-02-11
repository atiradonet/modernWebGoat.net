using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class LoginModel : PageModel
{
    private readonly AppDbContext _db;

    public LoginModel(AppDbContext db) => _db = db;

    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public string? Error { get; set; }
    public string? Success { get; set; }
    public int? FailedAttempts { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password))
        {
            Error = "Username and password are required.";
            return Page();
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == Username);
        if (user is null)
        {
            Error = "Invalid credentials.";
            return Page();
        }

        var hash = Md5Hash(Password);
        if (user.PasswordHash != hash)
        {
            // VULNERABILITY A04/A07: Tracked but never enforced — no lockout
            user.FailedLoginAttempts++;
            await _db.SaveChangesAsync();

            FailedAttempts = user.FailedLoginAttempts;
            Error = $"Invalid credentials. Failed attempts: {user.FailedLoginAttempts}";
            return Page();
        }

        user.FailedLoginAttempts = 0;
        await _db.SaveChangesAsync();

        Success = $"Welcome back, {user.Username}! Role: {user.Role}";
        return Page();
    }

    private static string Md5Hash(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }
}
