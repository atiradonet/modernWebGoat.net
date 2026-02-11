namespace ModernWebGoat.Endpoints;

public static class A10_SSRF
{
    public static void MapA10SsrfEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api").WithTags("A10 - SSRF");

        // VULNERABILITY A10: Unvalidated URL fetch — SSRF
        group.MapGet("/fetch", async (string? url, IHttpClientFactory httpClientFactory) =>
        {
            if (string.IsNullOrEmpty(url))
                return Results.BadRequest(new { error = "Provide a URL via ?url=" });

            try
            {
                // VULNERABLE: No URL validation — can access internal services,
                // cloud metadata endpoints (169.254.169.254), localhost, etc.
                var client = httpClientFactory.CreateClient();
                var response = await client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                return Results.Ok(new
                {
                    requestedUrl = url,
                    statusCode = (int)response.StatusCode,
                    contentLength = content.Length,
                    content = content.Length > 5000 ? content[..5000] + "... (truncated)" : content,
                    vulnerability = "No URL validation — attacker can access internal services, cloud metadata, etc."
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new
                {
                    requestedUrl = url,
                    error = ex.Message
                });
            }
        });

        // VULNERABILITY A10: POST version for form submissions
        group.MapPost("/fetch", async (FetchRequest request, IHttpClientFactory httpClientFactory) =>
        {
            if (string.IsNullOrEmpty(request.Url))
                return Results.BadRequest(new { error = "Provide a URL" });

            try
            {
                var client = httpClientFactory.CreateClient();
                var response = await client.GetAsync(request.Url);
                var content = await response.Content.ReadAsStringAsync();

                return Results.Ok(new
                {
                    requestedUrl = request.Url,
                    statusCode = (int)response.StatusCode,
                    content = content.Length > 5000 ? content[..5000] + "... (truncated)" : content
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
    }

    private record FetchRequest(string Url);
}
