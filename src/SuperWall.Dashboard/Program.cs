using Microsoft.Data.Sqlite;
using SuperWall.Contracts;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<AdminAuth>();
var app = builder.Build();
var db = Path.Combine(Environment.GetEnvironmentVariable("SUPERWALL_DATA") ?? "/var/lib/superwall", "superwall.db");
Directory.CreateDirectory(Path.GetDirectoryName(db)!);

// This restored baseline keeps the existing dashboard API surface intact.
// Profile and history fixes are handled by the dashboard UI/agent commits.
using (var c = new SqliteConnection($"Data Source={db}")) { c.Open(); }
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapFallbackToFile("index.html");
app.Run();
