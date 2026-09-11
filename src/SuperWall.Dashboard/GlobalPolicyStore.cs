using System.Text.Json;
using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

namespace SuperWall.Dashboard;

public static class GlobalPolicyStore
{
    private const string Key = "global";

    public static void EnsureSchema(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS global_policy(id TEXT PRIMARY KEY, version INTEGER NOT NULL, json TEXT NOT NULL);";
        cmd.ExecuteNonQuery();

        using var check = c.CreateCommand();
        check.CommandText = "SELECT COUNT(1) FROM global_policy WHERE id=$id";
        check.Parameters.AddWithValue("$id", Key);
        if (Convert.ToInt32(check.ExecuteScalar()) == 0)
            Set(c, CreateDefault());
    }

    public static SuperWallPolicy Get(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM global_policy WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", Key);
        var json = cmd.ExecuteScalar() as string;
        if (string.IsNullOrWhiteSpace(json)) return CreateDefault();

        try
        {
            var policy = JsonSerializer.Deserialize<SuperWallPolicy>(json) ?? CreateDefault();
            policy.BlockedDomains ??= new List<string>();
            policy.BlockedDomains = NormalizeDomains(policy.BlockedDomains);
            return policy;
        }
        catch (JsonException)
        {
            return CreateDefault();
        }
    }

    public static void Set(SqliteConnection c, SuperWallPolicy policy)
    {
        policy ??= CreateDefault();
        policy.Version = Math.Max(1, policy.Version);
        policy.BlockedDomains = NormalizeDomains(policy.BlockedDomains ?? new List<string>());

        // The dashboard sends only the switches and domains it edits. Keep the
        // complete policy object valid and retry briefly if SQLite is momentarily busy.
        var json = JsonSerializer.Serialize(policy);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var cmd = c.CreateCommand();
                cmd.CommandText = "INSERT INTO global_policy(id,version,json) VALUES($id,$v,$j) ON CONFLICT(id) DO UPDATE SET version=$v,json=$j";
                cmd.Parameters.AddWithValue("$id", Key);
                cmd.Parameters.AddWithValue("$v", policy.Version);
                cmd.Parameters.AddWithValue("$j", json);
                cmd.ExecuteNonQuery();
                return;
            }
            catch (SqliteException) when (attempt < 3)
            {
                Thread.Sleep(75 * (attempt + 1));
            }
        }
    }

    // Global policy is authoritative for its switches and mandatory domains.
    // Device policies may add extra blocked domains, but cannot weaken a global setting.
    public static SuperWallPolicy Apply(SuperWallPolicy global, SuperWallPolicy device)
    {
        global.BlockedDomains ??= new List<string>();
        device.BlockedDomains ??= new List<string>();

        var effective = JsonSerializer.Deserialize<SuperWallPolicy>(JsonSerializer.Serialize(device)) ?? new SuperWallPolicy();
        effective.Version = Math.Max(global.Version, device.Version);
        effective.UrlBlockingEnabled = global.UrlBlockingEnabled;
        effective.BlockedDomains = global.BlockedDomains
            .Concat(device.BlockedDomains)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(NormalizeDomain)
            .Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        effective.SearchHistoryEnabled = global.SearchHistoryEnabled;
        effective.DownloadsBlocked = global.DownloadsBlocked;
        effective.LockBrowserInstallation = global.LockBrowserInstallation;
        effective.BlockPortableBrowsers = global.BlockPortableBrowsers;
        if (!string.IsNullOrWhiteSpace(global.DashboardUrl)) effective.DashboardUrl = global.DashboardUrl;
        if (!string.IsNullOrWhiteSpace(global.DownloadPinHash)) effective.DownloadPinHash = global.DownloadPinHash;
        if (!string.IsNullOrWhiteSpace(global.DownloadPinSalt)) effective.DownloadPinSalt = global.DownloadPinSalt;
        return effective;
    }

    private static SuperWallPolicy CreateDefault() => new()
    {
        Version = 1,
        Profile = RiskProfile.Low,
        UrlBlockingEnabled = true,
        BlockedDomains = new() { "tiktok.com", "youtube.com", "roblox.com", "pornhub.com" },
        SearchHistoryEnabled = true,
        DownloadsBlocked = true,
        DashboardUrl = "https://superwall.hvmc.nl",
        LockBrowserInstallation = true,
        BlockPortableBrowsers = true
    };

    private static List<string> NormalizeDomains(IEnumerable<string> domains) => domains
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(NormalizeDomain)
        .Where(x => x.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static string NormalizeDomain(string value) => value.Trim().Trim('.').ToLowerInvariant();
}
