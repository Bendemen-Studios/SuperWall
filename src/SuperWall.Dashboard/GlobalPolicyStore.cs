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
        return string.IsNullOrWhiteSpace(json) ? CreateDefault() : JsonSerializer.Deserialize<SuperWallPolicy>(json) ?? CreateDefault();
    }

    public static void Set(SqliteConnection c, SuperWallPolicy policy)
    {
        policy.Version = Math.Max(1, policy.Version);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO global_policy(id,version,json) VALUES($id,$v,$j) ON CONFLICT(id) DO UPDATE SET version=$v,json=$j";
        cmd.Parameters.AddWithValue("$id", Key);
        cmd.Parameters.AddWithValue("$v", policy.Version);
        cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(policy));
        cmd.ExecuteNonQuery();
    }

    public static SuperWallPolicy Apply(SuperWallPolicy global, SuperWallPolicy device)
    {
        var effective = JsonSerializer.Deserialize<SuperWallPolicy>(JsonSerializer.Serialize(device)) ?? new SuperWallPolicy();
        effective.Version = Math.Max(global.Version, device.Version);
        effective.UrlBlockingEnabled = global.UrlBlockingEnabled || device.UrlBlockingEnabled;
        effective.BlockedDomains = global.BlockedDomains
            .Concat(device.BlockedDomains)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(NormalizeDomain)
            .Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        effective.SearchHistoryEnabled = global.SearchHistoryEnabled || device.SearchHistoryEnabled;
        effective.DownloadsBlocked = global.DownloadsBlocked || device.DownloadsBlocked;
        effective.LockBrowserInstallation = global.LockBrowserInstallation || device.LockBrowserInstallation;
        effective.BlockPortableBrowsers = global.BlockPortableBrowsers || device.BlockPortableBrowsers;
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

    private static string NormalizeDomain(string value) => value.Trim().Trim('.').ToLowerInvariant();
}
