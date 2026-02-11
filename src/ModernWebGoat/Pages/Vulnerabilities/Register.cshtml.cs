using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;
using ModernWebGoat.Models;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class RegisterModel : PageModel
{
    private readonly AppDbContext _db;

    public RegisterModel(AppDbContext db) => _db = db;

    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    [BindProperty]
    public string? Email { get; set; }

    public string? Error { get; set; }
    public string? Success { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Password))
        {
            Error = "Username and password are required.";
            return Page();
        }

        // VULNERABILITY A07: No password complexity requirements at all
        // Single char passwords accepted

        if (await _db.Users.AnyAsync(u => u.Username == Username))
        {
            Error = "Username already exists.";
            return Page();
        }

        var user = new User
        {
            Username = Username,
            PasswordHash = Md5Hash(Password),
            Email = Email ?? "",
            Role = "user",
            SSN = "",
            CreditCard = "",
            ApiKey = $"sk-{Username}-{Guid.NewGuid()}"
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        Success = $"Account created! Username: {user.Username}, Password hash (MD5): {user.PasswordHash}";
        return Page();
    }

    private static string Md5Hash(string input)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLower();
    }
}
