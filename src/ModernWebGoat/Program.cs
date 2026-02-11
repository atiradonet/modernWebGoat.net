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

// HttpClient for SSRF demos (A10)
builder.Services.AddHttpClient();

// VULNERABILITY A05: No rate limiting configured
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

// VULNERABILITY A01/A05: Overly permissive CORS
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

// VULNERABILITY A05: Developer exception page enabled unconditionally (exposes stack traces in production)
app.UseDeveloperExceptionPage();

// VULNERABILITY A05: No HTTPS redirection
// app.UseHttpsRedirection();  — intentionally omitted

// VULNERABILITY A05: No security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)

app.UseStaticFiles();

// VULNERABILITY A05: Directory browsing enabled — exposes file system structure
app.UseDirectoryBrowser(new DirectoryBrowserOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(builder.Environment.WebRootPath, "uploads")),
    RequestPath = "/uploads"
});

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Map all vulnerability endpoint groups
app.MapA01BrokenAccessControlEndpoints();
app.MapA02CryptographicFailuresEndpoints();
app.MapA03InjectionEndpoints();
app.MapA04InsecureDesignEndpoints();
app.MapA05SecurityMisconfigurationEndpoints();
app.MapA07AuthenticationFailuresEndpoints();
app.MapA08DataIntegrityFailuresEndpoints();
app.MapA09LoggingFailuresEndpoints();
app.MapA10SsrfEndpoints();

app.MapRazorPages();

app.Run();
