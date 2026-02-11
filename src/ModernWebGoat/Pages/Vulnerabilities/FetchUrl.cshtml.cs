using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class FetchUrlModel : PageModel
{
    private readonly IHttpClientFactory _httpClientFactory;

    public FetchUrlModel(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    [BindProperty]
    public new string? Url { get; set; }

    public string? ResponseContent { get; set; }
    public new int? StatusCode { get; set; }
    public string? Error { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrEmpty(Url))
        {
            Error = "Please provide a URL.";
            return Page();
        }

        try
        {
            // VULNERABILITY A01: No URL validation — SSRF
            var client = _httpClientFactory.CreateClient();
            var response = await client.GetAsync(Url);
            StatusCode = (int)response.StatusCode;
            var content = await response.Content.ReadAsStringAsync();
            ResponseContent = content.Length > 10000 ? content[..10000] + "\n... (truncated)" : content;
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }

        return Page();
    }
}
