using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;

namespace ModernWebGoat.Pages.Vulnerabilities;

public class SqlSearchModel : PageModel
{
    private readonly IConfiguration _config;

    public SqlSearchModel(IConfiguration config) => _config = config;

    [BindProperty(SupportsGet = true)]
    public string? Query { get; set; }

    public string? ExecutedSql { get; set; }
    public List<ProductResult> Results { get; set; } = new();
    public string? Error { get; set; }

    public void OnGet()
    {
        if (string.IsNullOrEmpty(Query)) return;

        try
        {
            var connectionString = _config.GetConnectionString("DefaultConnection");
            using var connection = new SqliteConnection(connectionString);
            connection.Open();

            // VULNERABILITY A03: SQL Injection — string concatenation
            ExecutedSql = $"SELECT Id, Name, Description, Price, Stock FROM Products WHERE Name LIKE '%{Query}%'";
            using var command = new SqliteCommand(ExecutedSql, connection);
            using var reader = command.ExecuteReader();

            while (reader.Read())
            {
                Results.Add(new ProductResult
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Description = reader.GetString(2),
                    Price = reader.GetDecimal(3),
                    Stock = reader.GetInt32(4)
                });
            }
        }
        catch (Exception ex)
        {
            Error = ex.Message;
        }
    }

    public class ProductResult
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public decimal Price { get; set; }
        public int Stock { get; set; }
    }
}
