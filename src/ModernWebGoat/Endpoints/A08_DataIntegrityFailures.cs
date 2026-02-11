using Newtonsoft.Json;

namespace ModernWebGoat.Endpoints;

public static class A08_DataIntegrityFailures
{
    public static void MapA08DataIntegrityFailuresEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/deserialize").WithTags("A08 - Software or Data Integrity Failures");

        // VULNERABILITY A08: Insecure deserialization with Newtonsoft.Json TypeNameHandling.All
        group.MapPost("/", async (HttpRequest request) =>
        {
            using var reader = new StreamReader(request.Body);
            var json = await reader.ReadToEndAsync();

            if (string.IsNullOrEmpty(json))
                return Results.BadRequest(new { error = "Provide JSON in the request body" });

            try
            {
                // VULNERABLE: TypeNameHandling.All allows arbitrary type instantiation
                // An attacker can craft JSON with $type to execute arbitrary code
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All
                };

                var result = JsonConvert.DeserializeObject(json, settings);

                return Results.Ok(new
                {
                    deserialized = result?.ToString(),
                    type = result?.GetType().FullName,
                    vulnerability = "TypeNameHandling.All allows arbitrary type instantiation via $type metadata"
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new
                {
                    error = ex.Message,
                    innerError = ex.InnerException?.Message
                });
            }
        });

        // Info endpoint about the vulnerability
        group.MapGet("/info", () =>
        {
            return Results.Ok(new
            {
                description = "Insecure deserialization via Newtonsoft.Json with TypeNameHandling.All",
                examples = new
                {
                    safePayload = "{\"Name\": \"test\", \"Value\": 42}",
                    dangerousPayload = "{\"$type\": \"System.IO.FileInfo, System.IO.FileSystem\", \"FileName\": \"/etc/passwd\"}",
                    notes = new[]
                    {
                        "TypeNameHandling.All trusts the $type field in JSON to determine the .NET type to instantiate",
                        "Attackers can use this to instantiate arbitrary types, potentially achieving RCE",
                        "The fix is to use TypeNameHandling.None (default) or a custom SerializationBinder"
                    }
                }
            });
        });
    }
}
