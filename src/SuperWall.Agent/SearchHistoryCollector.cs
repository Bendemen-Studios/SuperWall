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
        if (string.IsNullOrWhiteSpace(profile) || !Directory.Exists(profile))
        {
            AgentLogger.Error("History collection skipped: target Windows user profile could not be resolved.");
            return result;
        }

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

        var final = result
            .GroupBy(x => new { x.Browser, x.Url, x.Title, x.VisitedUtc })
            .Select(x => x.First())
            .OrderByDescending(x => x.VisitedUtc)
            .Take(25000)
            .ToList();

        AgentLogger.Info($"History collection finished. Profile={profile}, Records={final.Count}, RetentionDays={retentionDays}.");
        return final;
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
        if (!File.Exists(db)) return Array.Empty<HistoryRecord>();

        var temp = CreateSqliteSnapshot(db);
        if (temp is null) return Array.Empty<HistoryRecord>();

        try
        {
            using var con = new SqliteConnection($"Data Source={temp};Mode=ReadOnly;Default Timeout=30");
            con.Open();

            using var cmd = con.CreateCommand();
            // Read the visits table rather than urls.last_visit_time so the dashboard
            // receives every recorded browser visit, not only the last visit per URL.
            cmd.CommandText =
                "SELECT u.url,u.title,v.visit_time " +
                "FROM visits v INNER JOIN urls u ON u.id=v.url " +
                "WHERE v.visit_time > $min " +
                "ORDER BY v.visit_time DESC LIMIT 25000";
            cmd.Parameters.AddWithValue(
                "$min", (since.UtcTicks - ChromiumEpochTicks) / 10);

            using var r = cmd.ExecuteReader();
            var records = new List<HistoryRecord>();
            while (r.Read())
            {
                var micros = r.GetInt64(2);
                if (micros <= 0) continue;

                records.Add(new HistoryRecord
                {
                    Browser = browser,
                    Url = r.IsDBNull(0) ? "" : r.GetString(0),
                    Title = r.IsDBNull(1) ? "" : r.GetString(1),
                    VisitedUtc = new DateTimeOffset(
                        ChromiumEpochTicks + micros * 10, TimeSpan.Zero)
                });
            }

            return records;
        }
        catch (Exception ex)
        {
            AgentLogger.Error($"Could not read Chromium history snapshot '{db}'.", ex);
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
            var source = Path.Combine(profile, "places.sqlite");
            var temp = CreateSqliteSnapshot(source);
            if (temp is null) continue;

            try
            {
                using var con = new SqliteConnection($"Data Source={temp};Mode=ReadOnly;Default Timeout=30");
                con.Open();

                using var cmd = con.CreateCommand();
                // moz_historyvisits contains one row per actual visit.
                cmd.CommandText =
                    "SELECT p.url,p.title,h.visit_date " +
                    "FROM moz_historyvisits h INNER JOIN moz_places p ON p.id=h.place_id " +
                    "WHERE h.visit_date IS NOT NULL " +
                    "AND h.visit_date > $min " +
                    "ORDER BY h.visit_date DESC LIMIT 25000";
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
                        Url = r.IsDBNull(0) ? "" : r.GetString(0),
                        Title = r.IsDBNull(1) ? "" : r.GetString(1),
                        VisitedUtc = DateTimeOffset.UnixEpoch.AddTicks(micros * 10)
                    });
                }
            }
            catch (Exception ex)
            {
                AgentLogger.Error($"Could not read Firefox history snapshot '{source}'.", ex);
            }
            finally
            {
                TryDelete(temp);
            }
        }

        return records;
    }

    private static string? CreateSqliteSnapshot(string source)
    {
        if (!File.Exists(source)) return null;

        string? directory = null;
        SqliteConnection? sourceConnection = null;
        SqliteConnection? backupConnection = null;

        try
        {
            directory = Path.Combine(
                Path.GetTempPath(), $"superwall-history-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);

            var target = Path.Combine(directory, Path.GetFileName(source) + ".snapshot");

            // SQLite's online backup API correctly includes WAL contents and is
            // much safer than copying the main DB file while Chrome/Firefox is open.
            sourceConnection = new SqliteConnection(
                $"Data Source={source};Mode=ReadOnly;Default Timeout=30");
            sourceConnection.Open();

            backupConnection = new SqliteConnection(
                $"Data Source={target};Mode=ReadWriteCreate;Default Timeout=30");
            backupConnection.Open();

            sourceConnection.BackupDatabase(backupConnection);
            return target;
        }
        catch (Exception ex)
        {
            AgentLogger.Error($"Could not create SQLite history snapshot '{source}'.", ex);
            if (!string.IsNullOrWhiteSpace(directory)) TryDelete(directory);
            return null;
        }
        finally
        {
            backupConnection?.Dispose();
            sourceConnection?.Dispose();
        }
    }

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
