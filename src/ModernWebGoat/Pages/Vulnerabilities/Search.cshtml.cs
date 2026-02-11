using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class SearchModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Query { get; set; }

    public void OnGet() { }
}
