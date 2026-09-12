using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class SearchHistoryCollector
{
    public List<HistoryRecord> Collect(int retentionDays)
    {
        var since = DateTimeOffset.UtcNow.AddDays(-retentionDays);
        var result = new List<HistoryRecord>();
        var profile = WindowsUserScope.ProfilePath();
        if (string.IsNullOrWhiteSpace(profile) || !Directory.Exists(profile)) return result;

        var local = Path.Combine(profile, "AppData", "Local");
        result.AddRange(ReadChromium(Path.Combine(local, "Google", "Chrome", "User Data", "Default", "History"), "Chrome", since));
        result.AddRange(ReadChromium(Path.Combine(local, "Microsoft", "Edge", "User Data", "Default", "History"), "Edge", since));
        result.AddRange(ReadFirefox(Path.Combine(profile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"), since));

        return result.OrderByDescending(x => x.VisitedUtc).Take(25000).ToList();
    }

    private static IEnumerable<HistoryRecord> ReadChromium(string db, string browser, DateTimeOffset since)
    {
        var temp = CopyDatabase(db);
        if (temp is null) return Array.Empty<HistoryRecord>();

        try
        {
            var records = new List<HistoryRecord>();
            using var con = new SqliteConnection($"Data Source={temp}");
            con.Open();
            using var cmd = con.CreateCommand();
            cmd.CommandText = "SELECT url,title,last_visit_time FROM urls WHERE last_visit_time > $min ORDER BY last_visit_time DESC LIMIT 25000";
            cmd.Parameters.AddWithValue("$min", (since.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var micros = r.GetInt64(2);
                records.Add(new HistoryRecord
                {
                    Browser = browser,
                    Url = r.GetString(0),
                    Title = r.IsDBNull(1) ? "" : r.GetString(1),
                    VisitedUtc = DateTimeOffset.UnixEpoch.AddTicks(micros * 10)
                });
            }
            return records;
        }
        catch { return Array.Empty<HistoryRecord>(); }
        finally { TryDelete(temp); }
    }

    private static IEnumerable<HistoryRecord> ReadFirefox(string root, DateTimeOffset since)
    {
        if (!Directory.Exists(root)) return Array.Empty<HistoryRecord>();
        var records = new List<HistoryRecord>();

        foreach (var profile in Directory.EnumerateDirectories(root))
        {
            var temp = CopyDatabase(Path.Combine(profile, "places.sqlite"));
            if (temp is null) continue;
            try
            {
                using var con = new SqliteConnection($"Data Source={temp}");
                con.Open();
                using var cmd = con.CreateCommand();
                cmd.CommandText = "SELECT url,title,last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL AND last_visit_date > $min ORDER BY last_visit_date DESC LIMIT 25000";
                cmd.Parameters.AddWithValue("$min", (since.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var micros = r.GetInt64(2);
                    records.Add(new HistoryRecord
                    {
                        Browser = "Firefox",
                        Url = r.GetString(0),
                        Title = r.IsDBNull(1) ? "" : r.GetString(1),
                        VisitedUtc = DateTimeOffset.UnixEpoch.AddTicks(micros * 10)
                    });
                }
            }
            catch { }
            finally { TryDelete(temp); }
        }
        return records;
    }

    private static string? CopyDatabase(string source)
    {
        if (!File.Exists(source)) return null;
        try
        {
            var target = Path.Combine(Path.GetTempPath(), $"superwall-{Guid.NewGuid():N}.db");
            File.Copy(source, target, true);
            return target;
        }
        catch { return null; }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { }
    }
}
