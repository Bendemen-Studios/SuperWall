using System.Text.Json;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class DownloadGuard
{
    private static Timer? _timer;
    private static bool _enabled;
    private static DateTimeOffset _unlockedUntilUtc = DateTimeOffset.MinValue;
    private static readonly object Gate = new();
    private static readonly string StateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    public static void SetEnabled(bool enabled, SuperWallPolicy policy)
    {
        lock (Gate)
        {
            _enabled = enabled;
            if (!enabled) _unlockedUntilUtc = DateTimeOffset.MinValue;
        }

        _timer?.Dispose();
        _timer = enabled ? new Timer(_ => Sweep(policy), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2)) : null;
        if (!enabled) DeleteState();
    }

    public static bool Unlock(string pin, SuperWallPolicy policy)
    {
        lock (Gate)
        {
            if (!_enabled || !PinSecurity.Verify(pin, policy.DownloadPinHash, policy.DownloadPinSalt)) return false;
            _unlockedUntilUtc = DateTimeOffset.UtcNow.AddMinutes(10);
            PersistUnlockState(_unlockedUntilUtc);
        }

        // Browser enforcement is relaxed only for this short-lived in-memory window.
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
        lock (Gate)
        {
            if (_unlockedUntilUtc <= DateTimeOffset.UtcNow)
            {
                _unlockedUntilUtc = DateTimeOffset.MinValue;
                return false;
            }
            return true;
        }
    }

    private static void Sweep(SuperWallPolicy policy)
    {
        if (!_enabled) return;
        if (IsUnlocked()) return;

        BrowserPolicy.Apply(policy);
        DeleteState();

        foreach (var downloads in FindDownloadDirectories())
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(downloads).Where(IsLikelyDownload))
                {
                    var quarantine = Path.Combine(StateDir, "Quarantine");
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
            var name = Path.GetFileName(user);
            if (string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "Public", StringComparison.OrdinalIgnoreCase)) continue;
            var downloads = Path.Combine(user, "Downloads");
            if (Directory.Exists(downloads)) yield return downloads;
        }
    }

    private static bool IsLikelyDownload(string path) => !path.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".download", StringComparison.OrdinalIgnoreCase);

    private static void PersistUnlockState(DateTimeOffset expires)
    {
        try
        {
            Directory.CreateDirectory(StateDir);
            var path = Path.Combine(StateDir, "download-unlocked.json");
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(new { expiresUtc = expires }));
            File.Move(temp, path, true);
        }
        catch { }
    }

    private static void DeleteState()
    {
        try { File.Delete(Path.Combine(StateDir, "download-unlocked.json")); } catch { }
    }
}
