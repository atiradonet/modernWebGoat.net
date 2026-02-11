using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Tokens;
using ModernWebGoat.Data;
using ModernWebGoat.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// SQLite database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Razor Pages
builder.Services.AddRazorPages();

// HttpClient for SSRF demos (A01) and supply chain demos (A03)
builder.Services.AddHttpClient();

// VULNERABILITY A02: No rate limiting configured
// VULNERABILITY A07: Insecure JWT configuration
var jwtKey = builder.Configuration["Jwt:Key"]!; // Only 5 chars! (A07)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],

            // VULNERABILITY A07: Weak 5-character signing key
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),

            // VULNERABILITY A07: No expiration validation
            ValidateLifetime = false,

            // VULNERABILITY A07: No clock skew validation
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// VULNERABILITY A01/A02: Overly permissive CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// Seed database
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    SeedData.Initialize(db);
}

// VULNERABILITY A02: Developer exception page enabled unconditionally (exposes stack traces in production)
app.UseDeveloperExceptionPage();

// VULNERABILITY A02: No HTTPS redirection
// app.UseHttpsRedirection();  — intentionally omitted

// VULNERABILITY A02: No security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)

app.UseStaticFiles();

// VULNERABILITY A02: Directory browsing enabled — exposes file system structure
app.UseDirectoryBrowser(new DirectoryBrowserOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(builder.Environment.WebRootPath, "uploads")),
    RequestPath = "/uploads"
});

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Map all OWASP Top 10 (2025) vulnerability endpoint groups
app.MapA01BrokenAccessControlEndpoints();       // A01: Broken Access Control (+ SSRF)
app.MapA02SecurityMisconfigurationEndpoints();   // A02: Security Misconfiguration
app.MapA03SupplyChainFailuresEndpoints();        // A03: Software Supply Chain Failures (NEW)
app.MapA04CryptographicFailuresEndpoints();      // A04: Cryptographic Failures
app.MapA05InjectionEndpoints();                  // A05: Injection
app.MapA06InsecureDesignEndpoints();             // A06: Insecure Design
app.MapA07AuthenticationFailuresEndpoints();     // A07: Authentication Failures
app.MapA08DataIntegrityFailuresEndpoints();      // A08: Software or Data Integrity Failures
app.MapA09LoggingFailuresEndpoints();            // A09: Security Logging and Alerting Failures
app.MapA10ExceptionalConditionsEndpoints();      // A10: Mishandling of Exceptional Conditions (NEW)

app.MapRazorPages();

app.Run();
