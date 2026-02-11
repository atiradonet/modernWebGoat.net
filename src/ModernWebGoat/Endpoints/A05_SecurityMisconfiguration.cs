using System.Reflection;

namespace ModernWebGoat.Endpoints;

public static class A05_SecurityMisconfiguration
{
    public static void MapA05SecurityMisconfigurationEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/config").WithTags("A05 - Security Misconfiguration");

        // VULNERABILITY A05: Detailed error with full stack trace
        group.MapGet("/error", () =>
        {
            // This will throw and be caught by DeveloperExceptionPage,
            // exposing full stack trace, source code paths, etc.
            throw new InvalidOperationException(
                "This is a deliberately triggered error. " +
                "In production, DeveloperExceptionPage should NEVER be enabled. " +
                "It exposes source code paths, stack traces, and configuration details.");
        });

        // VULNERABILITY A05: Exposes app configuration and environment details
        group.MapGet("/info", (IConfiguration config, IWebHostEnvironment env) =>
        {
            return Results.Ok(new
            {
                environment = env.EnvironmentName,
                contentRoot = env.ContentRootPath,
                webRoot = env.WebRootPath,
                framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                machineName = Environment.MachineName,
                processId = Environment.ProcessId,
                securityHeaders = new
                {
                    csp = "NOT SET",
                    hsts = "NOT SET",
                    xFrameOptions = "NOT SET",
                    xContentTypeOptions = "NOT SET",
                    referrerPolicy = "NOT SET"
                },
                misconfigurations = new[]
                {
                    "DeveloperExceptionPage enabled unconditionally",
                    "Directory browsing enabled on /uploads",
                    "CORS allows any origin with any method",
                    "No HTTPS redirection",
                    "No security headers middleware",
                    "JWT signing key is only 5 characters",
                    "No rate limiting configured"
                }
            });
        });

        // VULNERABILITY A06: Dependency inventory (shows package versions for review)
        group.MapGet("/dependencies", () =>
        {
            var assemblies = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => !a.IsDynamic && a.GetName().Name != null)
                .OrderBy(a => a.GetName().Name)
                .Select(a => new
                {
                    name = a.GetName().Name,
                    version = a.GetName().Version?.ToString()
                })
                .ToList();

            return Results.Ok(new
            {
                note = "Review these dependencies for known CVEs using tools like 'dotnet list package --vulnerable'",
                knownRisks = new[]
                {
                    "Newtonsoft.Json with TypeNameHandling.All enables remote code execution",
                    "Microsoft.Data.Sqlite used with raw string concatenation enables SQL injection"
                },
                loadedAssemblies = assemblies
            });
        });
    }
}
