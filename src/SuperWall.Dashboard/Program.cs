using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("SUPERWALL_BIND") ?? "http://0.0.0.0:5080");
var app = builder.Build();

var dataDir = Path.Combine(AppContext.BaseDirectory, "data"); Directory.CreateDirectory(dataDir);
var db = Path.Combine(dataDir, "superwall.db");
var adminPassword = Environment.GetEnvironmentVariable("SUPERWALL_ADMIN_PASSWORD") ?? "";
var enrollmentKey = Environment.GetEnvironmentVariable("SUPERWALL_ENROLLMENT_KEY") ?? "";
if (string.IsNullOrWhiteSpace(adminPassword) || string.IsNullOrWhiteSpace(enrollmentKey)) throw new InvalidOperationException("SUPERWALL_ADMIN_PASSWORD and SUPERWALL_ENROLLMENT_KEY must be configured.");

using (var c = new SqliteConnection($"Data Source={db}"))
{
    c.Open(); using var cmd = c.CreateCommand();
    cmd.CommandText = "CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, name TEXT, os TEXT, profile TEXT NOT NULL DEFAULT 'Low', last_seen TEXT, agent_token_hash TEXT); CREATE TABLE IF NOT EXISTS policies(device_id TEXT PRIMARY KEY, json TEXT NOT NULL); CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, device_id TEXT, type TEXT, created TEXT, completed INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS history(device_id TEXT, browser TEXT, url TEXT, title TEXT, visited TEXT);";
    cmd.ExecuteNonQuery();
    EnsureColumn(c, "devices", "agent_token_hash", "TEXT");
}

bool IsAdmin(HttpRequest r) => r.Headers.TryGetValue("X-SuperWall-Admin", out var v) && FixedEquals(v.ToString(), adminPassword);
bool IsAgent(HttpRequest r, string id)
{
    if (!r.Headers.TryGetValue("X-SuperWall-Agent", out var supplied)) return false;
    using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT agent_token_hash FROM devices WHERE device_id=$d"; cmd.Parameters.AddWithValue("$d", id); var hash = cmd.ExecuteScalar() as string;
    return !string.IsNullOrWhiteSpace(hash) && FixedEquals(supplied.ToString(), hash, true);
}

app.UseDefaultFiles(); app.UseStaticFiles();

app.MapPost("/api/enroll/{id}", async (string id, HttpRequest req) =>
{
    if (!FixedEquals(req.Headers["X-SuperWall-Enrollment"].ToString(), enrollmentKey)) return Results.Unauthorized();
    var body = await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body) ?? new();
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    using var c = new SqliteConnection($"Data Source={db}"); c.Open();
    using var cmd = c.CreateCommand(); cmd.CommandText = @"INSERT INTO devices(device_id,name,os,profile,last_seen,agent_token_hash) VALUES($d,$n,$o,'Low',$t,$h) ON CONFLICT(device_id) DO UPDATE SET name=$n,os=$o,last_seen=$t,agent_token_hash=$h";
    cmd.Parameters.AddWithValue("$d", id); cmd.Parameters.AddWithValue("$n", body.GetValueOrDefault("computerName", id)); cmd.Parameters.AddWithValue("$o", body.GetValueOrDefault("osVersion", Environment.OSVersion.VersionString)); cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("O")); cmd.Parameters.AddWithValue("$h", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))); cmd.ExecuteNonQuery();
    return Results.Ok(new EnrollResponse { AgentToken = token, Policy = GetPolicy(c, id) });
});

app.MapGet("/api/devices", (HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); using var c = new SqliteConnection($"Data Source={db}"); c.Open(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT device_id,name,os,profile,last_seen FROM devices ORDER BY name"; using var r = cmd.ExecuteReader(); var list = new List<DeviceInfo>();
    while (r.Read()) { var seen = DateTimeOffset.Parse(r.GetString(4)); list.Add(new DeviceInfo { DeviceId=r.GetString(0), ComputerName=r.GetString(1), OsVersion=r.GetString(2), Profile=Enum.TryParse<RiskProfile>(r.GetString(3),true,out var p)?p:RiskProfile.Low, LastSeenUtc=seen, Online=DateTimeOffset.UtcNow-seen<TimeSpan.FromMinutes(3) }); }
    return Results.Ok(list);
});

app.MapPut("/api/devices/{id}/profile", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); var body=await JsonSerializer.DeserializeAsync<Dictionary<string,string>>(req.Body)??new(); var profile=body.TryGetValue("profile",out var p)&&Enum.TryParse<RiskProfile>(p,true,out var parsed)?parsed:RiskProfile.Low;
    using var c=new SqliteConnection($"Data Source={db}"); c.Open(); var policy=GetPolicy(c,id); policy.Profile=profile; policy.Version++; UpsertPolicy(c,id,policy); UpsertProfile(c,id,profile); return Results.Ok(policy);
});

app.MapGet("/api/devices/{id}/policy", (string id, HttpRequest req) => { if (!IsAdmin(req)) return Results.Unauthorized(); using var c=new SqliteConnection($"Data Source={db}"); c.Open(); return Results.Ok(GetPolicy(c,id)); });

app.MapPut("/api/devices/{id}/policy", async (string id, HttpRequest req) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized(); var policy=await JsonSerializer.DeserializeAsync<SuperWallPolicy>(req.Body)??new(); using var c=new SqliteConnection($"Data Source={db}"); c.Open(); var current=GetPolicy(c,id); policy.Version=Math.Max(current.Version+1,policy.Version); if (string.IsNullOrWhiteSpace(policy.DownloadPinHash)||string.IsNullOrWhiteSpace(policy.DownloadPinSalt)){policy.DownloadPinHash=current.DownloadPinHash;policy.DownloadPinSalt=current.DownloadPinSalt;} UpsertPolicy(c,id,policy); UpsertProfile(c,id,policy.Profile); return Results.Ok(policy);
});

app.MapPost("/api/devices/{id}/history/request", (string id,HttpRequest req)=>{if(!IsAdmin(req))return Results.Unauthorized();using var c=new SqliteConnection($"Data Source={db}");c.Open();using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO commands(id,device_id,type,created) VALUES($id,$d,'request_history',$t)";cmd.Parameters.AddWithValue("$id",Guid.NewGuid().ToString("N"));cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.ToString("O"));cmd.ExecuteNonQuery();return Results.Accepted();});

app.MapGet("/api/devices/{id}/history",(string id,HttpRequest req)=>{if(!IsAdmin(req))return Results.Unauthorized();using var c=new SqliteConnection($"Data Source={db}");c.Open();var policy=GetPolicy(c,id);using var cmd=c.CreateCommand();cmd.CommandText="SELECT browser,url,title,visited FROM history WHERE device_id=$d AND visited >= $from ORDER BY visited DESC LIMIT 5000";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$from",DateTimeOffset.UtcNow.AddDays(-policy.SearchHistoryRetentionDays).ToString("O"));using var r=cmd.ExecuteReader();var result=new List<HistoryRecord>();while(r.Read())result.Add(new HistoryRecord{Browser=r.GetString(0),Url=r.GetString(1),Title=r.GetString(2),VisitedUtc=DateTimeOffset.Parse(r.GetString(3))});return Results.Ok(result);});

app.MapPost("/api/devices/{id}/revoke",(string id,HttpRequest req)=>{if(!IsAdmin(req))return Results.Unauthorized();using var c=new SqliteConnection($"Data Source={db}");c.Open();using var cmd=c.CreateCommand();cmd.CommandText="UPDATE devices SET agent_token_hash=NULL WHERE device_id=$d";cmd.Parameters.AddWithValue("$d",id);cmd.ExecuteNonQuery();return Results.Ok();});

app.MapGet("/api/agent/{id}",(string id,HttpRequest req)=>{if(!IsAgent(req,id))return Results.Unauthorized();using var c=new SqliteConnection($"Data Source={db}");c.Open();TouchDevice(c,id);using var cmd=c.CreateCommand();cmd.CommandText="SELECT id,type FROM commands WHERE device_id=$d AND completed=0 ORDER BY created";cmd.Parameters.AddWithValue("$d",id);using var r=cmd.ExecuteReader();var commands=new List<AdminCommand>();while(r.Read())commands.Add(new AdminCommand{Id=r.GetString(0),Type=r.GetString(1)});return Results.Ok(new PolicyEnvelope{Policy=GetPolicy(c,id),Commands=commands});});

app.MapPost("/api/agent/{id}/history",async(string id,HttpRequest req)=>{if(!IsAgent(req,id))return Results.Unauthorized();var upload=await JsonSerializer.DeserializeAsync<HistoryUpload>(req.Body);if(upload is null||upload.DeviceId!=id)return Results.BadRequest();using var c=new SqliteConnection($"Data Source={db}");c.Open();var policy=GetPolicy(c,id);var cutoff=DateTimeOffset.UtcNow.AddDays(-policy.SearchHistoryRetentionDays);using var tx=c.BeginTransaction();using var ins=c.CreateCommand();ins.CommandText="INSERT INTO history(device_id,browser,url,title,visited) VALUES($d,$b,$u,$t,$v)";foreach(var x in upload.Records.Where(x=>x.VisitedUtc>=cutoff).Take(5000)){ins.Parameters.Clear();ins.Parameters.AddWithValue("$d",id);ins.Parameters.AddWithValue("$b",x.Browser[..Math.Min(80,x.Browser.Length)]);ins.Parameters.AddWithValue("$u",x.Url[..Math.Min(4096,x.Url.Length)]);ins.Parameters.AddWithValue("$t",x.Title[..Math.Min(512,x.Title.Length)]);ins.Parameters.AddWithValue("$v",x.VisitedUtc.ToString("O"));ins.ExecuteNonQuery();}using var clean=c.CreateCommand();clean.CommandText="DELETE FROM commands WHERE device_id=$d AND type='request_history'";clean.Parameters.AddWithValue("$d",id);clean.ExecuteNonQuery();tx.Commit();return Results.Ok();});

app.Run();

static bool FixedEquals(string supplied,string expected,bool expectedIsHex=false){try{var a=Encoding.UTF8.GetBytes(supplied);var b=expectedIsHex?Convert.FromHexString(expected):Encoding.UTF8.GetBytes(expected);return CryptographicOperations.FixedTimeEquals(SHA256.HashData(a),SHA256.HashData(b));}catch{return false;}}
static void EnsureColumn(SqliteConnection c,string table,string column,string type){using var cmd=c.CreateCommand();cmd.CommandText=$"PRAGMA table_info({table})";using var r=cmd.ExecuteReader();while(r.Read())if(string.Equals(r.GetString(1),column,StringComparison.OrdinalIgnoreCase))return;r.Close();using var add=c.CreateCommand();add.CommandText=$"ALTER TABLE {table} ADD COLUMN {column} {type}";add.ExecuteNonQuery();}
static SuperWallPolicy GetPolicy(SqliteConnection c,string id){using var cmd=c.CreateCommand();cmd.CommandText="SELECT json FROM policies WHERE device_id=$d";cmd.Parameters.AddWithValue("$d",id);var x=cmd.ExecuteScalar() as string;return string.IsNullOrWhiteSpace(x)?new SuperWallPolicy():JsonSerializer.Deserialize<SuperWallPolicy>(x)??new SuperWallPolicy();}
static void UpsertPolicy(SqliteConnection c,string id,SuperWallPolicy p){using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO policies(device_id,json) VALUES($d,$j) ON CONFLICT(device_id) DO UPDATE SET json=$j";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$j",JsonSerializer.Serialize(p));cmd.ExecuteNonQuery();}
static void UpsertProfile(SqliteConnection c,string id,RiskProfile p){using var cmd=c.CreateCommand();cmd.CommandText="INSERT INTO devices(device_id,name,os,profile,last_seen) VALUES($d,$n,$o,$p,$t) ON CONFLICT(device_id) DO UPDATE SET profile=$p";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$n",id);cmd.Parameters.AddWithValue("$o",Environment.OSVersion.VersionString);cmd.Parameters.AddWithValue("$p",p.ToString());cmd.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.ToString("O"));cmd.ExecuteNonQuery();}
static void TouchDevice(SqliteConnection c,string id){using var cmd=c.CreateCommand();cmd.CommandText="UPDATE devices SET last_seen=$t WHERE device_id=$d";cmd.Parameters.AddWithValue("$d",id);cmd.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.ToString("O"));cmd.ExecuteNonQuery();}
