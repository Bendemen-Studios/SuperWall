using System.Text.Json.Serialization;

namespace SuperWall.Contracts;

public enum RiskProfile { Low, High }

public sealed class SuperWallPolicy
{
    [JsonPropertyName("version")]
    public long Version { get; set; } = 1;

    [JsonPropertyName("profile")]
    public RiskProfile Profile { get; set; } = RiskProfile.Low;

    [JsonPropertyName("urlBlockingEnabled")]
    public bool UrlBlockingEnabled { get; set; } = true;

    [JsonPropertyName("blockedDomains")]
    public List<string> BlockedDomains { get; set; } = new() { "tiktok.com", "youtube.com", "roblox.com", "pornhub.com" };

    [JsonPropertyName("blockedCategories")]
    public List<string> BlockedCategories { get; set; } = new();

    [JsonPropertyName("allowedDomains")]
    public List<string> AllowedDomains { get; set; } = new();

    [JsonPropertyName("searchHistoryEnabled")]
    public bool SearchHistoryEnabled { get; set; } = true;

    [JsonPropertyName("searchHistoryRetentionDays")]
    public int SearchHistoryRetentionDays => Profile == RiskProfile.High ? 365 : 30;

    [JsonPropertyName("downloadsBlocked")]
    public bool DownloadsBlocked { get; set; } = true;

    [JsonPropertyName("dashboardUrl")]
    public string DashboardUrl { get; set; } = "https://superwall.hvmc.nl";

    [JsonPropertyName("lockBrowserInstallation")]
    public bool LockBrowserInstallation { get; set; } = true;

    [JsonPropertyName("blockPortableBrowsers")]
    public bool BlockPortableBrowsers { get; set; } = true;

    [JsonPropertyName("appBlockingEnabled")]
    public bool AppBlockingEnabled { get; set; } = false;

    [JsonPropertyName("blockedApplications")]
    public List<string> BlockedApplications { get; set; } = new();

    [JsonPropertyName("allowedApplications")]
    public List<string> AllowedApplications { get; set; } = new();

    [JsonPropertyName("blockedApplicationPaths")]
    public List<string> BlockedApplicationPaths { get; set; } = new();

    // Legacy compatibility only. These values are never serialized or used for approval.
    [JsonIgnore]
    [Obsolete("Download approval now uses local Windows administrator authentication.")]
    public string? DownloadPinHash { get; set; }

    [JsonIgnore]
    [Obsolete("Download approval now uses local Windows administrator authentication.")]
    public string? DownloadPinSalt { get; set; }
}

public sealed class DeviceInfo
{
    public string DeviceId { get; set; } = "";
    public string ComputerName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public RiskProfile Profile { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public bool Online { get; set; }
}

public sealed class HistoryRecord
{
    public string Browser { get; set; } = "";
    public string Url { get; set; } = "";
    public string Title { get; set; } = "";
    public DateTimeOffset VisitedUtc { get; set; }
}

public sealed class HistoryUpload
{
    public string DeviceId { get; set; } = "";
    public string RequestId { get; set; } = "";
    public List<HistoryRecord> Records { get; set; } = new();
}

public sealed class AdminCommand
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Type { get; set; } = "";
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class PolicyEnvelope
{
    public SuperWallPolicy Policy { get; set; } = new();
    public List<AdminCommand> Commands { get; set; } = new();
}

public sealed class EnrollResponse
{
    public string AgentToken { get; set; } = "";
    public SuperWallPolicy Policy { get; set; } = new();
}

public sealed class EnrollmentKeyInfo
{
    public string Id { get; set; } = "";
    public string Label { get; set; } = "";
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }
    public bool Used { get; set; }
    public bool Revoked { get; set; }
    public DateTimeOffset? UsedUtc { get; set; }
}

public sealed class CreateEnrollmentKeyRequest
{
    public string Label { get; set; } = "";
    public int ExpiresMinutes { get; set; } = 30;
}

public sealed class CreatedEnrollmentKey
{
    public EnrollmentKeyInfo Info { get; set; } = new();
    public string Key { get; set; } = "";
}