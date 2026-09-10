using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

var builder = WebApplication.CreateBuilder(args);
var bind = Environment.GetEnvironmentVariable("SUPERWALL_BIND") ?? "http://127.0.0.1:7080";
builder.WebHost.UseUrls(bind);
var app = builder.Build();

var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
Directory.CreateDirectory(dataDir);
var db = Path.Combine(dataDir, "superwall.db");
var requireHttps = !string.Equals(Environment.GetEnvironmentVariable("SUPERWALL_ALLOW_HTTP"), "1", StringComparison.Ordinal);
var adminPassword = Environment.GetEnvironmentVariable("SUPERWALL_ADMIN_PASSWORD") ?? "";
var sessions = new ConcurrentDictionary<string, DateTimeOffset>();

using (var c = new SqliteConnection($"Data Source={db}"))
{
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, name TEXT, os TEXT, profile TEXT NOT NULL DEFAULT 'Low', last_seen TEXT, agent_token_hash TEXT);
CREATE TABLE IF NOT EXISTS policies(device_id TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, device_id TEXT, type TEXT, created TEXT, completed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS history(device_id TEXT, browser TEXT, url TEXT, title TEXT, visited TEXT, request_id TEXT);
CREATE TABLE IF NOT EXISTS enrollment_keys(id TEXT PRIMARY KEY, label TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_utc TEXT NOT NULL, expires_utc TEXT NOT NULL, used_utc TEXT, revoked_utc TEXT);";
    cmd.ExecuteNonQuery();
    EnsureColumn(c, "devices", "agent_token_hash", "TEXT");
    EnsureColumn(c, "history", "request_id", "TEXT");
    PolicyProfiles.EnsureSchema(c);
}

if (string.IsNullOrWhiteSpace(adminPassword)) throw new InvalidOperationException("SUPERWALL_ADMIN_PASSWORD must be configured.");

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
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)); sessions[token] = DateTimeOffset.UtcNow.AddHours(8);
    req.HttpContext.Response.Cookies.Append("superwall_admin", token, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/", MaxAge = TimeSpan.FromHours(8), IsEssential = true });
    return Results.Ok(new { ok = true });
});

app.MapPost("/api/admin/logout", (HttpRequest req) =>
{
    if (req.Cookies.TryGetValue("superwall_admin", out var token)) sessions.TryRemove(token, out _);
    req.HttpContext.Response.Cookies.Delete("superwall_admin", new CookieOptions { Path = "/", Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict }); return Results.Ok();
});
app.MapGet("/api/admin/session", (HttpRequest req) => IsAdmin(req) ? Results.Ok(new { authenticated = true }) : Results.Unauthorized());

app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/api/admin") && ctx.Request.Path != "/api/admin/login" && ctx.Request.Path != "/api/admin/logout" && !IsAdmin(ctx.Request)) { ctx.Response.StatusCode = 401; return; }
    await next();
});

app.MapGet("/api/devices", (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT device_id,name,os,profile,last_seen FROM devices ORDER BY name"; using var r = cmd.ExecuteReader(); var list = new List<DeviceInfo>();
    while (r.Read()) { var seen = DateTimeOffset.Parse(r.GetString(4)); list.Add(new DeviceInfo { DeviceId = r.GetString(0), ComputerName = r.GetString(1), OsVersion = r.GetString(2), Profile = ParseProfile(r.GetString(3)), LastSeenUtc = seen, Online = DateTimeOffset.UtcNow - seen < TimeSpan.FromMinutes(3) }); }
    return Results.Ok(list);
});

app.MapGet("/api/admin/profiles", (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); return Results.Ok(new[] { PolicyProfiles.Get(c, RiskProfile.Low), PolicyProfiles.Get(c, RiskProfile.High) });
});

app.MapGet("/api/admin/profiles/{profile}", (string profile, HttpRequest req) =>
{
    if (!IsAdmin(req) || !Enum.TryParse<RiskProfile>(profile, true, out var p)) return Results.NotFound(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); return Results.Ok(PolicyProfiles.Get(c, p));
});

app.MapPut("/api/admin/profiles/{profile}", async (string profile, HttpRequest req) =>
{
    if (!IsAdmin(req) || !Enum.TryParse<RiskProfile>(profile, true, out var p)) return Results.NotFound(); var policy = await JsonSerializer.DeserializeAsync<SuperWallPolicy>(req.Body) ?? new SuperWallPolicy(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); var current = PolicyProfiles.Get(c, p); policy.Profile = p; policy.Version = Math.Max(current.Version + 1, policy.Version); policy.SearchHistoryEnabled = true; policy.DashboardUrl = "https://superwall.hvmc.nl"; PolicyProfiles.Set(c, p, policy); return Results.Ok(policy);
});

app.MapPut("/api/devices/{id}/profile", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); var body = await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body) ?? new(); if (!body.TryGetValue("profile", out var raw) || !Enum.TryParse<RiskProfile>(raw, true, out var profile)) return Results.BadRequest(new { error = "Invalid profile" }); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); var central = PolicyProfiles.Get(c, profile); var current = GetPolicy(c, id); current.Profile = profile; current.Version = Math.Max(current.Version + 1, central.Version + 1); current.BlockedDomains = new List<string>(central.BlockedDomains); current.UrlBlockingEnabled = central.UrlBlockingEnabled; current.SearchHistoryEnabled = central.SearchHistoryEnabled; current.DownloadsBlocked = central.DownloadsBlocked; current.DownloadPinHash = central.DownloadPinHash; current.DownloadPinSalt = central.DownloadPinSalt; current.LockBrowserInstallation = central.LockBrowserInstallation; current.BlockPortableBrowsers = central.BlockPortableBrowsers; current.DashboardUrl = central.DashboardUrl; UpsertPolicy(c, id, current); return Results.Ok(current);
});

app.MapGet("/api/devices/{id}/policy", (string id, HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); return Results.Ok(GetPolicy(c, id)); });

app.MapPut("/api/devices/{id}/policy", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); var policy = await JsonSerializer.DeserializeAsync<SuperWallPolicy>(req.Body) ?? new(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); var current = GetPolicy(c, id); policy.Version = Math.Max(current.Version + 1, policy.Version); if (string.IsNullOrWhiteSpace(policy.DownloadPinHash) || string.IsNullOrWhiteSpace(policy.DownloadPinSalt)) { policy.DownloadPinHash = current.DownloadPinHash; policy.DownloadPinSalt = current.DownloadPinSalt; } UpsertPolicy(c, id, policy); UpsertProfile(c, id, policy.Profile); return Results.Ok(policy);
});

app.MapPost("/api/devices/{id}/history/request", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var check = c.CreateCommand(); check.CommandText = "SELECT COUNT(1) FROM commands WHERE device_id=$d AND type='request_history' AND completed=0"; check.Parameters.AddWithValue("$d", id); if (Convert.ToInt32(check.ExecuteScalar()) > 0) return Results.Conflict(new { error = "A history request is already pending for this device." }); var requestId = Guid.NewGuid().ToString("N"); using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO commands(id,device_id,type,created,completed) VALUES($id,$d,'request_history',$t,0)"; cmd.Parameters.AddWithValue("$id", requestId); cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.ExecuteNonQuery(); return Results.Accepted(value: new { requestId });
});

app.MapGet("/api/devices/{id}/history", (string id, HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); var policy = GetPolicy(c, id); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT browser,url,title,visited FROM history WHERE device_id=$d AND visited >= $from ORDER BY visited DESC LIMIT 5000"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$from", DateTimeOffset.UtcNow.AddDays(-policy.SearchHistoryRetentionDays).ToString("O")); using var r = cmd.ExecuteReader(); var result = new List<HistoryRecord>(); while (r.Read()) result.Add(new HistoryRecord { Browser = r.GetString(0), Url = r.GetString(1), Title = r.GetString(2), VisitedUtc = DateTimeOffset.Parse(r.GetString(3)) }); return Results.Ok(result); });

app.MapPost("/api/devices/{id}/revoke", (string id, HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE devices SET agent_token_hash=NULL WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); return Results.Ok(cmd.ExecuteNonQuery()); });

app.MapGet("/api/admin/enrollment-keys", (HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,label,created_utc,expires_utc,used_utc,revoked_utc FROM enrollment_keys ORDER BY created_utc DESC"; using var r = cmd.ExecuteReader(); var result = new List<EnrollmentKeyInfo>(); while (r.Read()) { var used = !r.IsDBNull(4); var revoked = !r.IsDBNull(5); result.Add(new EnrollmentKeyInfo { Id = r.GetString(0), Label = r.GetString(1), CreatedUtc = DateTimeOffset.Parse(r.GetString(2)), ExpiresUtc = DateTimeOffset.Parse(r.GetString(3)), Used = used, Revoked = revoked, UsedUtc = used ? DateTimeOffset.Parse(r.GetString(4)) : null }); } return Results.Ok(result); });

app.MapPost("/api/admin/enrollment-keys", async (HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); var body = await JsonSerializer.DeserializeAsync<CreateEnrollmentKeyRequest>(req.Body) ?? new(); var minutes = Math.Clamp(body.ExpiresMinutes, 5, 1440); var label = string.IsNullOrWhiteSpace(body.Label) ? "Windows device" : body.Label.Trim(); if (label.Length > 80) label = label[..80]; var id = Guid.NewGuid().ToString("N"); var plain = "SWK-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace("+", "-").Replace("/", "_").TrimEnd('='); var created = DateTimeOffset.UtcNow; var expires = created.AddMinutes(minutes); var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(plain))); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO enrollment_keys(id,label,key_hash,created_utc,expires_utc) VALUES($i,$l,$h,$c,$e)"; cmd.Parameters.AddWithValue("$i", id); cmd.Parameters.AddWithValue("$l", label); cmd.Parameters.AddWithValue("$h", hash); cmd.Parameters.AddWithValue("$c", created.ToString("O")); cmd.Parameters.AddWithValue("$e", expires.ToString("O")); cmd.ExecuteNonQuery(); return Results.Ok(new CreatedEnrollmentKey { Info = new EnrollmentKeyInfo { Id = id, Label = label, CreatedUtc = created, ExpiresUtc = expires }, Key = plain }); });

app.MapPost("/api/admin/enrollment-keys/{id}/revoke", (string id, HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE enrollment_keys SET revoked_utc=$t WHERE id=$i AND used_utc IS NULL AND revoked_utc IS NULL"; cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.Parameters.AddWithValue("$i", id); var changed = cmd.ExecuteNonQuery(); return changed == 1 ? Results.Ok() : Results.NotFound(); });

app.MapPost("/api/enroll/{id}", async (string id, HttpRequest req) => { if (!IsSecure(req) || !req.Headers.TryGetValue("X-SuperWall-Enrollment", out var presented)) return Results.Unauthorized(); var supplied = presented.ToString().Trim(); if (supplied.Length < 12 || supplied.Length > 128) return Results.Unauthorized(); var suppliedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(supplied))); var body = await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body) ?? new(); var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)); var now = DateTimeOffset.UtcNow; using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var tx = c.BeginTransaction(); string? keyId = null; using (var keyCmd = c.CreateCommand()) { keyCmd.Transaction = tx; keyCmd.CommandText = "SELECT id FROM enrollment_keys WHERE key_hash=$h AND used_utc IS NULL AND revoked_utc IS NULL AND expires_utc > $n LIMIT 1"; keyCmd.Parameters.AddWithValue("$h", suppliedHash); keyCmd.Parameters.AddWithValue("$n", now.ToString("O")); keyId = keyCmd.ExecuteScalar() as string; } if (keyId is null) { tx.Rollback(); return Results.Unauthorized(); } using (var useCmd = c.CreateCommand()) { useCmd.Transaction = tx; useCmd.CommandText = "UPDATE enrollment_keys SET used_utc=$u WHERE id=$i AND used_utc IS NULL AND revoked_utc IS NULL"; useCmd.Parameters.AddWithValue("$u", now.ToString("O")); useCmd.Parameters.AddWithValue("$i", keyId); if (useCmd.ExecuteNonQuery() != 1) { tx.Rollback(); return Results.Unauthorized(); } } using (var deviceCmd = c.CreateCommand()) { deviceCmd.Transaction = tx; deviceCmd.CommandText = "INSERT INTO devices(device_id,name,os,profile,last_seen,agent_token_hash) VALUES($d,$n,$o,'Low',$t,$h) ON CONFLICT(device_id) DO UPDATE SET name=$n,os=$o,last_seen=$t,agent_token_hash=$h,profile='Low'"; deviceCmd.Parameters.AddWithValue("$d", id); deviceCmd.Parameters.AddWithValue("$n", body.GetValueOrDefault("computerName", id)); deviceCmd.Parameters.AddWithValue("$o", body.GetValueOrDefault("osVersion", "Windows")); deviceCmd.Parameters.AddWithValue("$t", now.ToString("O")); deviceCmd.Parameters.AddWithValue("$h", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))); deviceCmd.ExecuteNonQuery(); } tx.Commit(); using var c2 = new SqliteConnection($"Data Source={db}"); c2.Open(); EnsureProfilePolicy(c2, id, RiskProfile.Low); return Results.Ok(new EnrollResponse { AgentToken = token, Policy = GetPolicy(c2, id) }); });

app.MapGet("/api/agent/{id}", (string id, HttpRequest req) => { if (!IsAgent(req, id)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); EnsureDevice(c, id); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,type FROM commands WHERE device_id=$d AND completed=0 ORDER BY created"; cmd.Parameters.AddWithValue("$d", id); using var r = cmd.ExecuteReader(); var commands = new List<AdminCommand>(); while (r.Read()) commands.Add(new AdminCommand { Id = r.GetString(0), Type = r.GetString(1) }); return Results.Ok(new PolicyEnvelope { Policy = GetPolicy(c, id), Commands = commands }); });

app.MapPost("/api/agent/{id}/history", async (string id, HttpRequest req) => { if (!IsAgent(req, id)) return Results.Unauthorized(); var upload = await JsonSerializer.DeserializeAsync<HistoryUpload>(req.Body); if (upload is null || !string.Equals(upload.DeviceId, id, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(upload.RequestId)) return Results.BadRequest(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); var cutoff = DateTimeOffset.UtcNow.AddDays(-GetPolicy(c, id).SearchHistoryRetentionDays); using var tx = c.BeginTransaction(); using (var verify = c.CreateCommand()) { verify.Transaction = tx; verify.CommandText = "SELECT COUNT(1) FROM commands WHERE id=$id AND device_id=$d AND type='request_history' AND completed=0"; verify.Parameters.AddWithValue("$id", upload.RequestId); verify.Parameters.AddWithValue("$d", id); if (Convert.ToInt32(verify.ExecuteScalar()) != 1) { tx.Rollback(); return Results.Conflict(new { error = "History request is not pending." }); } } using (var ins = c.CreateCommand()) { ins.Transaction = tx; ins.CommandText = "INSERT INTO history(device_id,browser,url,title,visited,request_id) VALUES($d,$b,$u,$t,$v,$r)"; foreach (var x in upload.Records.Where(x => x.VisitedUtc >= cutoff).Take(5000)) { ins.Parameters.Clear(); ins.Parameters.AddWithValue("$d", id); ins.Parameters.AddWithValue("$b", Truncate(x.Browser,80)); ins.Parameters.AddWithValue("$u", Truncate(x.Url,4096)); ins.Parameters.AddWithValue("$t", Truncate(x.Title,512)); ins.Parameters.AddWithValue("$v", x.VisitedUtc.ToString("O")); ins.Parameters.AddWithValue("$r", upload.RequestId); ins.ExecuteNonQuery(); } } using (var clean = c.CreateCommand()) { clean.Transaction = tx; clean.CommandText = "UPDATE commands SET completed=1 WHERE id=$id AND device_id=$d AND type='request_history' AND completed=0"; clean.Parameters.AddWithValue("$id", upload.RequestId); clean.Parameters.AddWithValue("$d", id); clean.ExecuteNonQuery(); } tx.Commit(); return Results.Ok(); });

app.Run();

static string HashForCompare(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
static string Truncate(string value, int max) => string.IsNullOrEmpty(value) ? "" : value.Length <= max ? value : value[..max];
static RiskProfile ParseProfile(string value) => Enum.TryParse<RiskProfile>(value, true, out var p) ? p : RiskProfile.Low;
static SuperWallPolicy GetPolicy(SqliteConnection c, string id)
{
    using var profileCmd = c.CreateCommand(); profileCmd.CommandText = "SELECT profile FROM devices WHERE device_id=$d"; profileCmd.Parameters.AddWithValue("$d", id); var profile = ParseProfile(profileCmd.ExecuteScalar() as string ?? "Low");
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT json FROM policies WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); var x = cmd.ExecuteScalar() as string; return string.IsNullOrWhiteSpace(x) ? PolicyProfiles.Get(c, profile) : JsonSerializer.Deserialize<SuperWallPolicy>(x) ?? PolicyProfiles.Get(c, profile);
}
static void UpsertPolicy(SqliteConnection c, string id, SuperWallPolicy p) { using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO policies(device_id,json) VALUES($d,$j) ON CONFLICT(device_id) DO UPDATE SET json=$j"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(p)); cmd.ExecuteNonQuery(); }
static void UpsertProfile(SqliteConnection c, string id, RiskProfile p) { using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE devices SET profile=$p WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$p", p.ToString()); cmd.ExecuteNonQuery(); }
static void EnsureProfilePolicy(SqliteConnection c, string id, RiskProfile p) { UpsertPolicy(c, id, PolicyProfiles.Get(c, p)); }
static void EnsureDevice(SqliteConnection c, string id) { using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE devices SET last_seen=$t WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.ExecuteNonQuery(); }
static void EnsureColumn(SqliteConnection c, string table, string column, string type) { using var cmd = c.CreateCommand(); cmd.CommandText = $"PRAGMA table_info({table})"; using var r = cmd.ExecuteReader(); while (r.Read()) if (string.Equals(r.GetString(1), column, StringComparison.OrdinalIgnoreCase)) return; r.Close(); using var add = c.CreateCommand(); add.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {type}"; add.ExecuteNonQuery(); }
