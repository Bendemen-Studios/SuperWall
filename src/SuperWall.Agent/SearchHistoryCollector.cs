using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class SearchHistoryCollector
{
    private static readonly long ChromiumEpochTicks =
        DateTimeOffset.UnixEpoch.UtcTicks - TimeSpan.FromSeconds(11644473600L).Ticks;

    public List<HistoryRecord> Collect(int retentionDays)
    {
        if (retentionDays <= 0) return new();

        var since = DateTimeOffset.UtcNow.AddDays(-retentionDays);
        var result = new List<HistoryRecord>();
        var profile = WindowsUserScope.ProfilePath();
        if (string.IsNullOrWhiteSpace(profile) || !Directory.Exists(profile)) return result;

        var local = Path.Combine(profile, "AppData", "Local");
        var roaming = Path.Combine(profile, "AppData", "Roaming");

        // Chromium-family browsers can have multiple profiles (Default, Profile 1, ...)
        // and each profile has its own History database.
        var chromiumBrowsers = new[]
        {
            ("Chrome", Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Edge", Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Vivaldi", Path.Combine(local, "Vivaldi", "User Data")),
            ("Opera", Path.Combine(roaming, "Opera Software", "Opera Stable")),
            ("Opera GX", Path.Combine(roaming, "Opera Software", "Opera GX Stable")),
            ("Chromium", Path.Combine(local, "Chromium", "User Data")),
            ("Arc", Path.Combine(local, "The Browser Company", "Arc", "User Data"))
        };

        foreach (var (browser, userData) in chromiumBrowsers)
            result.AddRange(ReadChromiumProfiles(userData, browser, since));

        // Firefox stores history in places.sqlite, one database per Firefox profile.
        result.AddRange(ReadFirefox(
            Path.Combine(roaming, "Mozilla", "Firefox", "Profiles"), since));

        return result
            .GroupBy(x => new { x.Browser, x.Url, x.Title, x.VisitedUtc })
            .Select(x => x.First())
            .OrderByDescending(x => x.VisitedUtc)
            .Take(25000)
            .ToList();
    }

    private static IEnumerable<HistoryRecord> ReadChromiumProfiles(
        string userData,
        string browser,
        DateTimeOffset since)
    {
        if (!Directory.Exists(userData)) return Array.Empty<HistoryRecord>();

        var databases = new List<string>();

        try
        {
            // Most Chromium browsers use a directory per profile.
            // Opera's stable path itself can contain the History database.
            var direct = Path.Combine(userData, "History");
            if (File.Exists(direct)) databases.Add(direct);

            foreach (var directory in Directory.EnumerateDirectories(userData))
            {
                var history = Path.Combine(directory, "History");
                if (File.Exists(history)) databases.Add(history);
            }
        }
        catch
        {
            // A browser can change/remove its profile while we're enumerating it.
        }

        var records = new List<HistoryRecord>();
        foreach (var db in databases.Distinct(StringComparer.OrdinalIgnoreCase))
            records.AddRange(ReadChromium(db, browser, since));

        return records;
    }

    private static IEnumerable<HistoryRecord> ReadChromium(
        string db,
        string browser,
        DateTimeOffset since)
    {
        var temp = CopyDatabase(db);
        if (temp is null) return Array.Empty<HistoryRecord>();

        try
        {
            var records = new List<HistoryRecord>();
            using var con = new SqliteConnection($"Data Source={temp}");
            con.Open();

            using var cmd = con.CreateCommand();
            cmd.CommandText =
                "SELECT url,title,last_visit_time FROM urls " +
                "WHERE last_visit_time > $min " +
                "ORDER BY last_visit_time DESC LIMIT 25000";
            cmd.Parameters.AddWithValue(
                "$min", (since.UtcTicks - ChromiumEpochTicks) / 10);

            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var micros = r.GetInt64(2);
                if (micros <= 0) continue;

                records.Add(new HistoryRecord
                {
                    Browser = browser,
                    Url = r.GetString(0),
                    Title = r.IsDBNull(1) ? "" : r.GetString(1),
                    VisitedUtc = new DateTimeOffset(
                        ChromiumEpochTicks + micros * 10, TimeSpan.Zero)
                });
            }

            return records;
        }
        catch
        {
            return Array.Empty<HistoryRecord>();
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static IEnumerable<HistoryRecord> ReadFirefox(
        string root,
        DateTimeOffset since)
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
                cmd.CommandText =
                    "SELECT url,title,last_visit_date FROM moz_places " +
                    "WHERE last_visit_date IS NOT NULL " +
                    "AND last_visit_date > $min " +
                    "ORDER BY last_visit_date DESC LIMIT 25000";
                cmd.Parameters.AddWithValue(
                    "$min",
                    (since.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);

                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var micros = r.GetInt64(2);
                    if (micros <= 0) continue;

                    records.Add(new HistoryRecord
                    {
                        Browser = "Firefox",
                        Url = r.GetString(0),
                        Title = r.IsDBNull(1) ? "" : r.GetString(1),
                        VisitedUtc = DateTimeOffset.UnixEpoch.AddTicks(micros * 10)
                    });
                }
            }
            catch
            {
                // Ignore a profile that is unavailable or has an incompatible schema.
            }
            finally
            {
                TryDelete(temp);
            }
        }

        return records;
    }

    private static string? CopyDatabase(string source)
    {
        if (!File.Exists(source)) return null;

        string? directory = null;
        try
        {
            directory = Path.Combine(
                Path.GetTempPath(), $"superwall-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);

            var target = Path.Combine(directory, Path.GetFileName(source));
            File.Copy(source, target, true);

            foreach (var suffix in new[] { "-wal", "-shm" })
            {
                var sidecar = source + suffix;
                if (File.Exists(sidecar))
                    File.Copy(sidecar, target + suffix, true);
            }

            return target;
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(directory)) TryDelete(directory);
            return null;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, true);
            else File.Delete(path);
        }
        catch { }
    }
}
