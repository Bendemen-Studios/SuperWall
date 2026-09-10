using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

var builder = WebApplication.CreateBuilder(args);
var bind = Environment.GetEnvironmentVariable("SUPERWALL_BIND") ?? "http://0.0.0.0:7080";
builder.WebHost.UseUrls(bind);
var app = builder.Build();

var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
Directory.CreateDirectory(dataDir);
var db = Path.Combine(dataDir, "superwall.db");
var requireHttps = !string.Equals(Environment.GetEnvironmentVariable("SUPERWALL_ALLOW_HTTP"), "1", StringComparison.Ordinal);
var adminPassword = Environment.GetEnvironmentVariable("SUPERWALL_ADMIN_PASSWORD") ?? "";
var enrollmentKey = Environment.GetEnvironmentVariable("SUPERWALL_ENROLLMENT_KEY") ?? "";
var sessions = new ConcurrentDictionary<string, DateTimeOffset>();

using (var c = new SqliteConnection($"Data Source={db}"))
{
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, name TEXT, os TEXT, profile TEXT NOT NULL DEFAULT 'Low', last_seen TEXT, agent_token_hash TEXT);
CREATE TABLE IF NOT EXISTS policies(device_id TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, device_id TEXT, type TEXT, created TEXT, completed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS history(device_id TEXT, browser TEXT, url TEXT, title TEXT, visited TEXT);
";
    cmd.ExecuteNonQuery();
    EnsureColumn(c, "devices", "agent_token_hash", "TEXT");
}

if (string.IsNullOrWhiteSpace(adminPassword)) throw new InvalidOperationException("SUPERWALL_ADMIN_PASSWORD must be configured.");
if (string.IsNullOrWhiteSpace(enrollmentKey)) throw new InvalidOperationException("SUPERWALL_ENROLLMENT_KEY must be configured.");

bool IsSecure(HttpRequest r) => !requireHttps || r.IsHttps || string.Equals(r.Headers["X-Forwarded-Proto"], "https", StringComparison.OrdinalIgnoreCase) || r.Host.Host is "localhost" or "127.0.0.1";

bool IsAdmin(HttpRequest r)
{
    if (!IsSecure(r)) return false;
    if (r.Cookies.TryGetValue("superwall_admin", out var token) && sessions.TryGetValue(token, out var expiry) && expiry > DateTimeOffset.UtcNow)
    {
        sessions[token] = DateTimeOffset.UtcNow.AddHours(8);
        return true;
    }
    return false;
}

bool IsAgent(HttpRequest r, string id)
{
    if (!IsSecure(r)) return false;
    if (!r.Headers.TryGetValue("X-SuperWall-Agent", out var value)) return false;
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT agent_token_hash FROM devices WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id);
    var stored = cmd.ExecuteScalar() as string;
    return !string.IsNullOrWhiteSpace(stored) && CryptographicOperations.FixedTimeEquals(Convert.FromHexString(stored), SHA256.HashData(Encoding.UTF8.GetBytes(value.ToString())));
}

app.Use(async (ctx, next) =>
{
    if (requireHttps && !IsSecure(ctx.Request) && ctx.Request.Path.StartsWithSegments("/api")) { ctx.Response.StatusCode = 400; await ctx.Response.WriteAsync("HTTPS is required."); return; }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapPost("/api/admin/login", async (HttpRequest req) =>
{
    if (!IsSecure(req)) return Results.BadRequest(new { error = "HTTPS required" });
    var body = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(req.Body) ?? new();
    var supplied = body.GetValueOrDefault("password", "");
    var ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(HashForCompare(supplied)), Encoding.UTF8.GetBytes(HashForCompare(adminPassword)));
    if (!ok) return Results.Unauthorized();
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    sessions[token] = DateTimeOffset.UtcNow.AddHours(8);
    return Results.Json(new { ok = true }, new JsonSerializerOptions(), "application/json", 200, null, false);
});

app.MapPost("/api/admin/logout", (HttpRequest req) =>
{
    if (req.Cookies.TryGetValue("superwall_admin", out var token)) sessions.TryRemove(token, out _);
    return Results.Ok();
});

app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/api/admin") && ctx.Request.Path != "/api/admin/login" && ctx.Request.Path != "/api/admin/logout")
    {
        if (!IsAdmin(ctx.Request)) { ctx.Response.StatusCode = 401; return; }
    }
    await next();
});

app.MapGet("/api/devices", (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT device_id,name,os,profile,last_seen FROM devices ORDER BY name";
    using var r = cmd.ExecuteReader(); var list = new List<DeviceInfo>();
    while (r.Read())
    {
        var seen = DateTimeOffset.Parse(r.GetString(4));
        list.Add(new DeviceInfo { DeviceId = r.GetString(0), ComputerName = r.GetString(1), OsVersion = r.GetString(2), Profile = Enum.TryParse<RiskProfile>(r.GetString(3), true, out var p) ? p : RiskProfile.Low, LastSeenUtc = seen, Online = DateTimeOffset.UtcNow - seen < TimeSpan.FromMinutes(3) });
    }
    return Results.Ok(list);
});

app.MapPut("/api/devices/{id}/profile", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    var body = await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body) ?? new();
    var profile = body.TryGetValue("profile", out var p) && Enum.TryParse<RiskProfile>(p, true, out var parsed) ? parsed : RiskProfile.Low;
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    var policy = GetPolicy(c, id); policy.Profile = profile; policy.Version++;
    UpsertPolicy(c, id, policy); UpsertProfile(c, id, profile); return Results.Ok(policy);
});

app.MapGet("/api/devices/{id}/policy", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); return Results.Ok(GetPolicy(c, id));
});

app.MapPut("/api/devices/{id}/policy", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    var policy = await JsonSerializer.DeserializeAsync<SuperWallPolicy>(req.Body) ?? new();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    var current = GetPolicy(c, id); policy.Version = Math.Max(current.Version + 1, policy.Version);
    if (string.IsNullOrWhiteSpace(policy.DownloadPinHash) || string.IsNullOrWhiteSpace(policy.DownloadPinSalt)) { policy.DownloadPinHash = current.DownloadPinHash; policy.DownloadPinSalt = current.DownloadPinSalt; }
    UpsertPolicy(c, id, policy); UpsertProfile(c, id, policy.Profile); return Results.Ok(policy);
});

app.MapPost("/api/devices/{id}/history/request", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO commands(id,device_id,type,created) VALUES($id,$d,'request_history',$t)"; cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N")); cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.ExecuteNonQuery(); return Results.Accepted();
});

app.MapGet("/api/devices/{id}/history", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    var policy = GetPolicy(c, id);
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT browser,url,title,visited FROM history WHERE device_id=$d AND visited >= $from ORDER BY visited DESC LIMIT 5000"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$from", DateTimeOffset.UtcNow.AddDays(-policy.SearchHistoryRetentionDays).ToString("O"));
    using var r = cmd.ExecuteReader(); var result = new List<HistoryRecord>(); while (r.Read()) result.Add(new HistoryRecord { Browser = r.GetString(0), Url = r.GetString(1), Title = r.GetString(2), VisitedUtc = DateTimeOffset.Parse(r.GetString(3)) }); return Results.Ok(result);
});

app.MapPost("/api/devices/{id}/revoke", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE devices SET agent_token_hash=NULL WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); cmd.ExecuteNonQuery(); return Results.Ok();
});

app.MapPost("/api/enroll/{id}", async (string id, HttpRequest req) =>
{
    if (!IsSecure(req) || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(req.Headers["X-SuperWall-Enrollment"].ToString()), Encoding.UTF8.GetBytes(enrollmentKey))) return Results.Unauthorized();
    var body = await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body) ?? new();
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var tx = c.BeginTransaction();
    using var cmd = c.CreateCommand(); cmd.CommandText = @"INSERT INTO devices(device_id,name,os,profile,last_seen,agent_token_hash) VALUES($d,$n,$o,'Low',$t,$h) ON CONFLICT(device_id) DO UPDATE SET name=$n,os=$o,last_seen=$t,agent_token_hash=$h";
    cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$n", body.GetValueOrDefault("computerName", id)); cmd.Parameters.AddWithValue("$o", body.GetValueOrDefault("osVersion", "Windows")); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.Parameters.AddWithValue("$h", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))); cmd.ExecuteNonQuery(); tx.Commit();
    using var c2 = new SqliteConnection($"Data Source={db}"); c2.Open(); return Results.Ok(new EnrollResponse { AgentToken = token, Policy = GetPolicy(c2, id) });
});

app.MapGet("/api/agent/{id}", (string id, HttpRequest req) =>
{
    if (!IsAgent(req, id)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); EnsureDevice(c, id, req);
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,type FROM commands WHERE device_id=$d AND completed=0 ORDER BY created"; cmd.Parameters.AddWithValue("$d", id); using var r = cmd.ExecuteReader(); var commands = new List<AdminCommand>(); while (r.Read()) commands.Add(new AdminCommand { Id = r.GetString(0), Type = r.GetString(1) });
    return Results.Ok(new PolicyEnvelope { Policy = GetPolicy(c, id), Commands = commands });
});

app.MapPost("/api/agent/{id}/history", async (string id, HttpRequest req) =>
{
    if (!IsAgent(req, id)) return Results.Unauthorized();
    var upload = await JsonSerializer.DeserializeAsync<HistoryUpload>(req.Body); if (upload is null || !string.Equals(upload.DeviceId, id, StringComparison.Ordinal)) return Results.BadRequest();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); var policy = GetPolicy(c, id); var cutoff = DateTimeOffset.UtcNow.AddDays(-policy.SearchHistoryRetentionDays); using var tx = c.BeginTransaction();
    using var ins = c.CreateCommand(); ins.CommandText = "INSERT INTO history(device_id,browser,url,title,visited) VALUES($d,$b,$u,$t,$v)";
    foreach (var x in upload.Records.Where(x => x.VisitedUtc >= cutoff).Take(5000)) { ins.Parameters.Clear(); ins.Parameters.AddWithValue("$d", id); ins.Parameters.AddWithValue("$b", x.Browser[..Math.Min(80, x.Browser.Length)]); ins.Parameters.AddWithValue("$u", x.Url[..Math.Min(4096, x.Url.Length)]); ins.Parameters.AddWithValue("$t", x.Title[..Math.Min(512, x.Title.Length)]); ins.Parameters.AddWithValue("$v", x.VisitedUtc.ToString("O")); ins.ExecuteNonQuery(); }
    using var clean = c.CreateCommand(); clean.CommandText = "DELETE FROM commands WHERE device_id=$d AND type='request_history'"; clean.Parameters.AddWithValue("$d", id); clean.ExecuteNonQuery(); tx.Commit(); return Results.Ok();
});

app.Run();

static string HashForCompare(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
static void EnsureColumn(SqliteConnection c, string table, string column, string type) { using var cmd = c.CreateCommand(); cmd.CommandText = $"PRAGMA table_info({table})"; using var r = cmd.ExecuteReader(); while (r.Read()) if (string.Equals(r.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return; r.Close(); using var add = c.CreateCommand(); add.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {type}"; add.ExecuteNonQuery(); }
static SuperWallPolicy GetPolicy(SqliteConnection c, string id) { using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT json FROM policies WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); var x = cmd.ExecuteScalar() as string; return string.IsNullOrWhiteSpace(x) ? new SuperWallPolicy() : JsonSerializer.Deserialize<SuperWallPolicy>(x) ?? new SuperWallPolicy(); }
static void UpsertPolicy(SqliteConnection c, string id, SuperWallPolicy p) { using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO policies(device_id,json) VALUES($d,$j) ON CONFLICT(device_id) DO UPDATE SET json=$j"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(p)); cmd.ExecuteNonQuery(); }
static void UpsertProfile(SqliteConnection c, string id, RiskProfile p) { using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO devices(device_id,name,os,profile,last_seen) VALUES($d,$n,$o,$p,$t) ON CONFLICT(device_id) DO UPDATE SET profile=$p"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$n", id); cmd.Parameters.AddWithValue("$o", "Windows"); cmd.Parameters.AddWithValue("$p", p.ToString()); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.ExecuteNonQuery(); }
static void EnsureDevice(SqliteConnection c, string id, HttpRequest req) { using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE devices SET last_seen=$t WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.ExecuteNonQuery(); }
