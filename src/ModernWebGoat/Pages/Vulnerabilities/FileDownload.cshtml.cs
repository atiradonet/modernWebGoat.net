using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class FileDownloadModel : PageModel
{
    private readonly IWebHostEnvironment _env;

    public FileDownloadModel(IWebHostEnvironment env) => _env = env;

    [BindProperty(SupportsGet = true)]
    public string? FileName { get; set; }

    public string? FileContent { get; set; }
    public string? ResolvedPath { get; set; }
    public string? Error { get; set; }

    public void OnGet()
    {
        if (string.IsNullOrEmpty(FileName)) return;

        // VULNERABILITY A01: Path traversal — no sanitization
        var filePath = Path.Combine(_env.WebRootPath, "uploads", FileName);
        ResolvedPath = filePath;

        try
        {
            if (System.IO.File.Exists(filePath))
            {
                FileContent = System.IO.File.ReadAllText(filePath);
            }
            else
            {
                Error = $"File not found: {filePath}";
            }
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }
    }
}
