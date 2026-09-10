using System.Text.Json;
using Microsoft.Data.Sqlite;
using SuperWall.Contracts;

namespace SuperWall.Dashboard;

public static class PolicyProfiles
{
    public static void EnsureSchema(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS profile_policies(profile TEXT PRIMARY KEY, version INTEGER NOT NULL, json TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
        Ensure(c, RiskProfile.Low);
        Ensure(c, RiskProfile.High);
    }

    public static SuperWallPolicy Get(SqliteConnection c, RiskProfile profile)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM profile_policies WHERE profile=$p";
        cmd.Parameters.AddWithValue("$p", profile.ToString());
        var json = cmd.ExecuteScalar() as string;
        return string.IsNullOrWhiteSpace(json) ? CreateDefault(profile) : JsonSerializer.Deserialize<SuperWallPolicy>(json) ?? CreateDefault(profile);
    }

    public static void Set(SqliteConnection c, RiskProfile profile, SuperWallPolicy policy)
    {
        policy.Profile = profile;
        policy.Version = Math.Max(1, policy.Version);
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO profile_policies(profile,version,json) VALUES($p,$v,$j) ON CONFLICT(profile) DO UPDATE SET version=$v,json=$j";
        cmd.Parameters.AddWithValue("$p", profile.ToString());
        cmd.Parameters.AddWithValue("$v", policy.Version);
        cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(policy));
        cmd.ExecuteNonQuery();
    }

    public static RiskProfile ParseProfile(string? value) =>
        Enum.TryParse<RiskProfile>(value, true, out var profile) ? profile : RiskProfile.Low;

    public static SuperWallPolicy BuildEffective(SqliteConnection c, RiskProfile profile, SuperWallPolicy? overridePolicy = null)
    {
        var central = Get(c, profile);
        if (overridePolicy is null) return central;
        overridePolicy.Profile = profile;
        overridePolicy.Version = Math.Max(overridePolicy.Version, central.Version);
        overridePolicy.UrlBlockingEnabled = central.UrlBlockingEnabled;
        overridePolicy.BlockedDomains = new List<string>(central.BlockedDomains);
        overridePolicy.SearchHistoryEnabled = central.SearchHistoryEnabled;
        overridePolicy.DownloadsBlocked = central.DownloadsBlocked;
        overridePolicy.DownloadPinHash = central.DownloadPinHash;
        overridePolicy.DownloadPinSalt = central.DownloadPinSalt;
        overridePolicy.LockBrowserInstallation = central.LockBrowserInstallation;
        overridePolicy.BlockPortableBrowsers = central.BlockPortableBrowsers;
        overridePolicy.DashboardUrl = central.DashboardUrl;
        return overridePolicy;
    }

    private static void Ensure(SqliteConnection c, RiskProfile profile)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(1) FROM profile_policies WHERE profile=$p";
        cmd.Parameters.AddWithValue("$p", profile.ToString());
        if (Convert.ToInt32(cmd.ExecuteScalar()) != 0) return;
        Set(c, profile, CreateDefault(profile));
    }

    private static SuperWallPolicy CreateDefault(RiskProfile profile) => new()
    {
        Version = 1,
        Profile = profile,
        UrlBlockingEnabled = true,
        BlockedDomains = new() { "tiktok.com", "youtube.com", "roblox.com", "pornhub.com" },
        SearchHistoryEnabled = true,
        DownloadsBlocked = true,
        DashboardUrl = "https://superwall.hvmc.nl",
        LockBrowserInstallation = true,
        BlockPortableBrowsers = true
    };
}
