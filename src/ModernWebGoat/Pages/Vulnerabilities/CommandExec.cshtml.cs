using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class CommandExecModel : PageModel
{
    [BindProperty]
    public string? Host { get; set; }

    public string? CommandOutput { get; set; }
    public string? CommandError { get; set; }
    public string? ExecutedCommand { get; set; }

    public void OnGet() { }

    public void OnPost()
    {
        if (string.IsNullOrEmpty(Host)) return;

        // VULNERABILITY A05: Command injection — user input passed to shell
        ExecutedCommand = $"ping -c 2 {Host}";

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "/bin/sh",
                Arguments = $"-c \"ping -c 2 {Host}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };

        process.Start();
        CommandOutput = process.StandardOutput.ReadToEnd();
        CommandError = process.StandardError.ReadToEnd();
        process.WaitForExit();
    }
}
