using Microsoft.Data.Sqlite;
using SuperWall.Contracts;
using System.Text.Json;

namespace SuperWall.Dashboard;

public static class ApplicationInventoryEndpoints
{
    public static void MapApplicationInventory(this WebApplication app, string db, Func<HttpRequest,bool> isAdmin, Func<HttpRequest,string,bool> isAgent)
    {
        app.MapGet("/api/devices/{id}/applications", (string id, HttpRequest req) =>
        {
            if (!isAdmin(req)) return Results.Unauthorized();
            using var c = new SqliteConnection($"Data Source={db}"); c.Open(); EnsureTable(c);
            using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT name,version,publisher,path,reported_utc FROM installed_apps WHERE device_id=$d ORDER BY name"; cmd.Parameters.AddWithValue("$d", id);
            using var r = cmd.ExecuteReader(); var result = new List<object>();
            while (r.Read()) result.Add(new { name=r.GetString(0), version=r.GetString(1), publisher=r.GetString(2), path=r.GetString(3), reportedUtc=r.GetString(4) });
            return Results.Ok(result);
        });
        app.MapPost("/api/agent/{id}/applications", async (string id, HttpRequest req) =>
        {
            if (!isAgent(req,id)) return Results.Unauthorized();
            var upload = await JsonSerializer.DeserializeAsync<InstalledApplicationsUpload>(req.Body);
            if (upload is null || upload.DeviceId != id) return Results.BadRequest();
            using var c = new SqliteConnection($"Data Source={db}"); c.Open(); EnsureTable(c); using var tx = c.BeginTransaction();
            using (var del=c.CreateCommand()) { del.Transaction=tx; del.CommandText="DELETE FROM installed_apps WHERE device_id=$d"; del.Parameters.AddWithValue("$d",id); del.ExecuteNonQuery(); }
            using (var ins=c.CreateCommand()) { ins.Transaction=tx; ins.CommandText="INSERT INTO installed_apps(device_id,name,version,publisher,path,reported_utc) VALUES($d,$n,$v,$p,$x,$t)"; foreach(var x in upload.Applications.Take(2000)){ins.Parameters.Clear();ins.Parameters.AddWithValue("$d",id);ins.Parameters.AddWithValue("$n",Truncate(x.Name,256));ins.Parameters.AddWithValue("$v",Truncate(x.Version,80));ins.Parameters.AddWithValue("$p",Truncate(x.Publisher,256));ins.Parameters.AddWithValue("$x",Truncate(x.Path,4096));ins.Parameters.AddWithValue("$t",DateTimeOffset.UtcNow.ToString("O"));ins.ExecuteNonQuery();} }
            using (var clean=c.CreateCommand()) { clean.Transaction=tx; clean.CommandText="UPDATE commands SET completed=1 WHERE device_id=$d AND type='request_app_inventory' AND completed=0"; clean.Parameters.AddWithValue("$d",id); clean.ExecuteNonQuery(); }
            tx.Commit(); return Results.Ok(new { count=Math.Min(upload.Applications.Count,2000) });
        });
    }
    private static void EnsureTable(SqliteConnection c){using var cmd=c.CreateCommand();cmd.CommandText="CREATE TABLE IF NOT EXISTS installed_apps(device_id TEXT NOT NULL,name TEXT NOT NULL,version TEXT,publisher TEXT,path TEXT,reported_utc TEXT NOT NULL,PRIMARY KEY(device_id,name,version,publisher));";cmd.ExecuteNonQuery();}
    private static string Truncate(string value,int max)=>string.IsNullOrEmpty(value)?"":value.Length<=max?value:value[..max];
}
