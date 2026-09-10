using System.Text.Json;
using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("SUPERWALL_BIND") ?? "http://0.0.0.0:5080");
var app = builder.Build();

var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
Directory.CreateDirectory(dataDir);
var db = Path.Combine(dataDir, "superwall.db");
using (var c = new SqliteConnection($"Data Source={db}"))
{
    c.Open();
    using var cmd = c.CreateCommand();
    cmd.CommandText = "CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, name TEXT, os TEXT, profile TEXT NOT NULL DEFAULT 'Low', last_seen TEXT); CREATE TABLE IF NOT EXISTS policies(device_id TEXT PRIMARY KEY, json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, device_id TEXT, type TEXT, created TEXT, completed INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS history(device_id TEXT, browser TEXT, url TEXT, title TEXT, visited TEXT);";
    cmd.ExecuteNonQuery();
}

var defaultPolicy = new SuperWallPolicy();
var adminPassword = Environment.GetEnvironmentVariable("SUPERWALL_ADMIN_PASSWORD") ?? "change-me";
var agentToken = Environment.GetEnvironmentVariable("SUPERWALL_AGENT_TOKEN") ?? "change-me";

bool IsAdmin(HttpRequest r) => r.Headers.TryGetValue("X-SuperWall-Admin", out var v) && v == adminPassword;
bool IsAgent(HttpRequest r) => r.Headers.TryGetValue("X-SuperWall-Agent", out var v) && v == agentToken;

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/devices", (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT device_id,name,os,profile,last_seen FROM devices ORDER BY name";
    using var r = cmd.ExecuteReader(); var list = new List<DeviceInfo>();
    while (r.Read()) list.Add(new DeviceInfo { DeviceId = r.GetString(0), ComputerName = r.GetString(1), OsVersion = r.GetString(2), Profile = Enum.TryParse<RiskProfile>(r.GetString(3), true, out var p) ? p : RiskProfile.Low, LastSeenUtc = DateTimeOffset.Parse(r.GetString(4)), Online = DateTimeOffset.UtcNow - DateTimeOffset.Parse(r.GetString(4)) < TimeSpan.FromMinutes(3) });
    return Results.Ok(list);
});

app.MapPut("/api/devices/{id}/profile", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    var body = await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body) ?? new();
    var profile = body.TryGetValue("profile", out var p) && Enum.TryParse<RiskProfile>(p, true, out var parsed) ? parsed : RiskProfile.Low;
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var tx = c.BeginTransaction();
    var policy = GetPolicy(c, id); policy.Profile = profile;
    UpsertPolicy(c, id, policy); UpsertProfile(c, id, profile);
    tx.Commit();
    return Results.Ok(policy);
});

app.MapGet("/api/devices/{id}/policy", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    return Results.Ok(GetPolicy(c, id));
});

app.MapPut("/api/devices/{id}/policy", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    var policy = await JsonSerializer.DeserializeAsync<SuperWallPolicy>(req.Body) ?? new();
    policy.Profile = policy.Profile;
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); UpsertPolicy(c, id, policy); UpsertProfile(c, id, policy.Profile);
    return Results.Ok(policy);
});

app.MapPost("/api/devices/{id}/history/request", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO commands(id,device_id,type,created) VALUES($id,$d,'request_history',$t)"; cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString("N")); cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.ExecuteNonQuery();
    return Results.Accepted();
});

app.MapGet("/api/devices/{id}/history", (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT browser,url,title,visited FROM history WHERE device_id=$d ORDER BY visited DESC LIMIT 5000"; cmd.Parameters.AddWithValue("$d", id);
    using var r = cmd.ExecuteReader(); var result = new List<HistoryRecord>(); while (r.Read()) result.Add(new HistoryRecord { Browser=r.GetString(0), Url=r.GetString(1), Title=r.GetString(2), VisitedUtc=DateTimeOffset.Parse(r.GetString(3)) }); return Results.Ok(result);
});

app.MapGet("/api/agent/{id}", (string id, HttpRequest req) =>
{
    if (!IsAgent(req)) return Results.Unauthorized();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    EnsureDevice(c, id, req);
    using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT id,type FROM commands WHERE device_id=$d AND completed=0 ORDER BY created"; cmd.Parameters.AddWithValue("$d", id); using var r = cmd.ExecuteReader(); var commands = new List<AdminCommand>(); while (r.Read()) commands.Add(new AdminCommand{Id=r.GetString(0),Type=r.GetString(1)});
    using var c2 = new SqliteConnection($"Data Source={db}"); c2.Open(); var policy=GetPolicy(c2,id); return Results.Ok(new PolicyEnvelope{Policy=policy,Commands=commands});
});

app.MapPost("/api/agent/{id}/history", async (string id, HttpRequest req) =>
{
    if (!IsAgent(req)) return Results.Unauthorized();
    var upload = await JsonSerializer.DeserializeAsync<HistoryUpload>(req.Body); if (upload is null) return Results.BadRequest();
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var tx=c.BeginTransaction();
    using var ins=c.CreateCommand(); ins.CommandText="INSERT INTO history(device_id,browser,url,title,visited) VALUES($d,$b,$u,$t,$v)";
    foreach(var x in upload.Records){ins.Parameters.Clear(); ins.Parameters.AddWithValue("$d",id); ins.Parameters.AddWithValue("$b",x.Browser); ins.Parameters.AddWithValue("$u",x.Url); ins.Parameters.AddWithValue("$t",x.Title); ins.Parameters.AddWithValue("$v",x.VisitedUtc.ToString("O")); ins.ExecuteNonQuery();}
    using var clean=c.CreateCommand(); clean.CommandText="DELETE FROM commands WHERE device_id=$d AND type='request_history'"; clean.Parameters.AddWithValue("$d",id); clean.ExecuteNonQuery(); tx.Commit(); return Results.Ok();
});

app.Run();

static SuperWallPolicy GetPolicy(SqliteConnection c,string id)
{
    using var cmd=c.CreateCommand(); cmd.CommandText="SELECT json FROM policies WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d",id); var x=cmd.ExecuteScalar() as string; return string.IsNullOrWhiteSpace(x)?new SuperWallPolicy():JsonSerializer.Deserialize<SuperWallPolicy>(x)??new SuperWallPolicy();
}
static void UpsertPolicy(SqliteConnection c,string id,SuperWallPolicy p){using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO policies(device_id,json) VALUES($d,$j) ON CONFLICT(device_id) DO UPDATE SET json=$j";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$j",JsonSerializer.Serialize(p));cmd.ExecuteNonQuery();}
static void UpsertProfile(SqliteConnection c,string id,RiskProfile p){using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO devices(device_id,name,os,profile,last_seen) VALUES($d,$n,$o,$p,$t) ON CONFLICT(device_id) DO UPDATE SET profile=$p";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$n",id);cmd.Parameters.AddWithValue("$o","");cmd.Parameters.AddWithValue("$p",p.ToString());cmd.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.ToString("O"));cmd.ExecuteNonQuery();}
static void EnsureDevice(SqliteConnection c,string id,HttpRequest req){using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO devices(device_id,name,os,profile,last_seen) VALUES($d,$n,$o,'Low',$t) ON CONFLICT(device_id) DO UPDATE SET last_seen=$t";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$n",req.Headers.UserAgent.ToString().Take(80).Aggregate("",(a,b)=>a+b));cmd.Parameters.AddWithValue("$o",Environment.OSVersion.VersionString);cmd.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.ToString("O"));cmd.ExecuteNonQuery();}
