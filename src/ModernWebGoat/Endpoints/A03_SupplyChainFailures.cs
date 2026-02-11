using System.Reflection;

namespace ModernWebGoat.Endpoints;

public static class A03_SupplyChainFailures
{
    public static void MapA03SupplyChainFailuresEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/supply-chain").WithTags("A03 - Software Supply Chain Failures");

        // VULNERABILITY A03: Loaded assembly inventory — exposes dependency versions for CVE research
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
                    "Microsoft.Data.Sqlite used with raw string concatenation enables SQL injection",
                    "No automated dependency scanning in CI/CD pipeline"
                },
                loadedAssemblies = assemblies
            });
        });

        // VULNERABILITY A03: No SBOM (Software Bill of Materials) generation
        group.MapGet("/sbom", () =>
        {
            return Results.Ok(new
            {
                sbomAvailable = false,
                vulnerability = "No SBOM is generated for this project. Without an SBOM, " +
                    "it is impossible to track transitive dependencies or respond quickly to supply chain incidents.",
                recommendations = new[]
                {
                    "Generate SBOM using 'dotnet CycloneDX' or 'syft'",
                    "Include SBOM in build artifacts and release packages",
                    "Monitor SBOM against vulnerability databases continuously"
                }
            });
        });

        // VULNERABILITY A03: No dependency pinning or lock file
        group.MapGet("/pinning", (IWebHostEnvironment env) =>
        {
            var csprojPath = Path.Combine(env.ContentRootPath, "ModernWebGoat.csproj");
            var csprojContent = File.Exists(csprojPath) ? File.ReadAllText(csprojPath) : "File not found";
            var lockFilePath = Path.Combine(env.ContentRootPath, "packages.lock.json");
            var lockFileExists = File.Exists(lockFilePath);

            return Results.Ok(new
            {
                csprojContent,
                lockFileExists,
                vulnerability = "No packages.lock.json found. Without a lock file, builds may pull " +
                    "different transitive dependency versions, enabling dependency confusion attacks.",
                recommendations = new[]
                {
                    "Enable lock file with <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> in .csproj",
                    "Commit packages.lock.json to source control",
                    "Use --locked-mode in CI builds to enforce exact versions"
                }
            });
        });

        // VULNERABILITY A03: Downloads package from arbitrary URL without hash/signature verification
        group.MapPost("/install-package", async (PackageInstallRequest request, IHttpClientFactory httpClientFactory) =>
        {
            if (string.IsNullOrEmpty(request.Url))
                return Results.BadRequest(new { error = "Provide a package URL" });

            try
            {
                // VULNERABLE: Downloads from arbitrary URL with no integrity verification
                var client = httpClientFactory.CreateClient();
                var response = await client.GetAsync(request.Url);
                var bytes = await response.Content.ReadAsByteArrayAsync();

                return Results.Ok(new
                {
                    downloadedFrom = request.Url,
                    sizeBytes = bytes.Length,
                    hashVerified = false,
                    signatureVerified = false,
                    vulnerability = "Package downloaded without verifying hash or cryptographic signature. " +
                        "An attacker performing a MITM or compromising the source could inject malicious code."
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
    }

    private record PackageInstallRequest(string Url);
}
