namespace ModernWebGoat.Endpoints;

public static class A02_SecurityMisconfiguration
{
    public static void MapA02SecurityMisconfigurationEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/config").WithTags("A02 - Security Misconfiguration");

        // VULNERABILITY A02: Detailed error with full stack trace
        group.MapGet("/error", () =>
        {
            // This will throw and be caught by DeveloperExceptionPage,
            // exposing full stack trace, source code paths, etc.
            throw new InvalidOperationException(
                "This is a deliberately triggered error. " +
                "In production, DeveloperExceptionPage should NEVER be enabled. " +
                "It exposes source code paths, stack traces, and configuration details.");
        });

        // VULNERABILITY A02: Exposes app configuration and environment details
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
    }
}
