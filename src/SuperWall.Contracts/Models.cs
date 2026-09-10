namespace SuperWall.Contracts;

public enum RiskProfile { Low, High }

public sealed class SuperWallPolicy
{
    public long Version { get; set; } = 1;
    public RiskProfile Profile { get; set; } = RiskProfile.Low;
    public bool UrlBlockingEnabled { get; set; } = true;
    public List<string> BlockedDomains { get; set; } = new() { "tiktok.com", "youtube.com", "roblox.com", "pornhub.com" };
    public bool SearchHistoryEnabled { get; set; } = true;
    public int SearchHistoryRetentionDays => Profile == RiskProfile.High ? 365 : 30;
    public bool DownloadsBlocked { get; set; } = true;
    public string DownloadPinHash { get; set; } = "";
    public string DownloadPinSalt { get; set; } = "";
    public string DashboardUrl { get; set; } = "";
    public bool LockBrowserInstallation { get; set; } = true;
    public bool BlockPortableBrowsers { get; set; } = true;
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
