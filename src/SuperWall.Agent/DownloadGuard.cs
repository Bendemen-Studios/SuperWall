using System.Text.Json;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class DownloadGuard
{
    private static Timer? _timer;
    private static volatile bool _enabled;
    private static volatile DateTimeOffset _unlockedUntilUtc;
    private static readonly object Gate = new();
    private static readonly string StateFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall", "download-unlocked.json");

    public static void SetEnabled(bool enabled, SuperWallPolicy policy)
    {
        _enabled = enabled;
        _timer?.Dispose();
        _timer = enabled ? new Timer(_ => Sweep(policy), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2)) : null;
        if (!enabled) { lock (Gate) _unlockedUntilUtc = DateTimeOffset.MinValue; try { File.Delete(StateFile); } catch { } }
    }

    public static bool Unlock(string pin, SuperWallPolicy policy)
    {
        if (!_enabled || string.IsNullOrWhiteSpace(policy.DownloadPinHash) || !PinSecurity.Verify(pin, policy.DownloadPinHash, policy.DownloadPinSalt)) return false;
        lock (Gate) _unlockedUntilUtc = DateTimeOffset.UtcNow.AddMinutes(10);
        Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
        File.WriteAllText(StateFile, JsonSerializer.Serialize(new { expiresUtc = _unlockedUntilUtc }));
        BrowserPolicy.Apply(new SuperWallPolicy { DownloadsBlocked = false });
        return true;
    }

    public static bool IsUnlocked() { lock (Gate) return _unlockedUntilUtc > DateTimeOffset.UtcNow; }

    private static void Sweep(SuperWallPolicy policy)
    {
        if (!_enabled || IsUnlocked()) return;
        BrowserPolicy.Apply(policy);
        var root = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
        if (!Directory.Exists(root)) return;
        foreach (var user in Directory.EnumerateDirectories(root))
        {
            var downloads = Path.Combine(user, "Downloads");
            if (!Directory.Exists(downloads)) continue;
            foreach (var file in Directory.EnumerateFiles(downloads).Where(IsLikelyDownload))
            {
                try
                {
                    var quarantine = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall", "Quarantine");
                    Directory.CreateDirectory(quarantine);
                    var target = Path.Combine(quarantine, Path.GetFileName(file));
                    if (File.Exists(target)) target = Path.Combine(quarantine, $"{Guid.NewGuid():N}-{Path.GetFileName(file)}");
                    File.Move(file, target);
                }
                catch { }
            }
        }
    }

    private static bool IsLikelyDownload(string path) => !path.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".part", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".download", StringComparison.OrdinalIgnoreCase);
}
