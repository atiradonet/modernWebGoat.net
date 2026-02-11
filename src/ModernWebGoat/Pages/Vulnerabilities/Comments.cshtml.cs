using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using ModernWebGoat.Data;
using ModernWebGoat.Models;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class CommentsModel : PageModel
{
    private readonly AppDbContext _db;

    public CommentsModel(AppDbContext db) => _db = db;

    public List<Comment> Comments { get; set; } = new();

    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public new string? Content { get; set; }

    public async Task OnGetAsync()
    {
        Comments = await _db.Comments.OrderByDescending(c => c.CreatedAt).ToListAsync();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Username) || string.IsNullOrEmpty(Content))
        {
            Comments = await _db.Comments.OrderByDescending(c => c.CreatedAt).ToListAsync();
            return Page();
        }

        // VULNERABILITY A05: No HTML sanitization — stored XSS
        var comment = new Comment
        {
            UserId = 0,
            Username = Username,
            Content = Content,
            CreatedAt = DateTime.UtcNow
        };

        _db.Comments.Add(comment);
        await _db.SaveChangesAsync();

        return RedirectToPage();
    }
}
