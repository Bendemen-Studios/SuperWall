using System.Text.Json;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class DownloadGuard
{
    private static Timer? _timer;
    private static bool _enabled;
    private static DateTimeOffset _unlockedUntilUtc = DateTimeOffset.MinValue;
    private static readonly object Gate = new();
    private static readonly string StateFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall", "download-unlocked.json");

    public static void SetEnabled(bool enabled, SuperWallPolicy policy)
    {
        _enabled = enabled;
        _timer?.Dispose();
        _timer = enabled ? new Timer(_ => Sweep(policy), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2)) : null;
        if (!enabled)
        {
            lock (Gate) _unlockedUntilUtc = DateTimeOffset.MinValue;
            DeleteState();
        }
    }

    public static bool Unlock(string pin, SuperWallPolicy policy)
    {
        lock (Gate)
        {
            if (!_enabled || !PinSecurity.Verify(pin, policy.DownloadPinHash, policy.DownloadPinSalt))
                return false;
            _unlockedUntilUtc = DateTimeOffset.UtcNow.AddMinutes(10);
            Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
            File.WriteAllText(StateFile, JsonSerializer.Serialize(new { expiresUtc = _unlockedUntilUtc }));
        }
        var unlockedPolicy = new SuperWallPolicy
        {
            Version = policy.Version,
            Profile = policy.Profile,
            UrlBlockingEnabled = policy.UrlBlockingEnabled,
            BlockedDomains = new List<string>(policy.BlockedDomains),
            SearchHistoryEnabled = policy.SearchHistoryEnabled,
            DownloadsBlocked = false,
            DownloadPinHash = policy.DownloadPinHash,
            DownloadPinSalt = policy.DownloadPinSalt,
            DashboardUrl = policy.DashboardUrl,
            LockBrowserInstallation = policy.LockBrowserInstallation,
            BlockPortableBrowsers = policy.BlockPortableBrowsers
        };
        BrowserPolicy.Apply(unlockedPolicy);
        return true;
    }

    public static bool IsUnlocked()
    {
        lock (Gate) return _unlockedUntilUtc > DateTimeOffset.UtcNow;
    }

    private static void Sweep(SuperWallPolicy policy)
    {
        if (!_enabled) return;
        if (IsUnlocked()) return;
        BrowserPolicy.Apply(policy);
        foreach (var downloads in FindDownloadDirectories())
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(downloads).Where(IsLikelyDownload))
                {
                    var quarantine = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall", "Quarantine");
                    Directory.CreateDirectory(quarantine);
                    var target = Path.Combine(quarantine, Path.GetFileName(file));
                    if (File.Exists(target)) target = Path.Combine(quarantine, $"{Guid.NewGuid():N}-{Path.GetFileName(file)}");
                    File.Move(file, target);
                }
            }
            catch { }
        }
    }

    private static IEnumerable<string> FindDownloadDirectories()
    {
        var root = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
        if (!Directory.Exists(root)) yield break;
        foreach (var user in Directory.EnumerateDirectories(root))
        {
            if (string.Equals(Path.GetFileName(user), "Default", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(Path.GetFileName(user), "Public", StringComparison.OrdinalIgnoreCase)) continue;
            var downloads = Path.Combine(user, "Downloads");
            if (Directory.Exists(downloads)) yield return downloads;
        }
    }

    private static bool IsLikelyDownload(string path) => !path.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".download", StringComparison.OrdinalIgnoreCase);

    private static void DeleteState() { try { File.Delete(StateFile); } catch { } }
}
