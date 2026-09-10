using System.Text.Json;

namespace SuperWall.Agent;

public static class DownloadGuard
{
    private static Timer? _timer;
    private static bool _enabled;
    private static bool _browserUnlocked;
    private static readonly string StateFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall", "download-unlocked.json");

    public static void SetEnabled(bool enabled)
    {
        _enabled = enabled;
        _timer?.Dispose();
        _timer = enabled ? new Timer(_ => Sweep(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2)) : null;
        if (!enabled) _browserUnlocked = false;
    }

    public static bool Unlock(string pin)
    {
        if (pin != "2003") return false;
        Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
        File.WriteAllText(StateFile, JsonSerializer.Serialize(new { expiresUtc = DateTimeOffset.UtcNow.AddMinutes(10) }));
        _browserUnlocked = true;
        BrowserPolicy.Apply(false);
        return true;
    }

    private static bool IsUnlocked()
    {
        try
        {
            var doc = JsonDocument.Parse(File.ReadAllText(StateFile));
            return doc.RootElement.GetProperty("expiresUtc").GetDateTimeOffset() > DateTimeOffset.UtcNow;
        }
        catch { return false; }
    }

    private static void Sweep()
    {
        if (!_enabled) return;
        if (IsUnlocked()) return;
        if (_browserUnlocked)
        {
            _browserUnlocked = false;
            BrowserPolicy.Apply(true);
        }
        foreach (var user in Directory.EnumerateDirectories(Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users")))
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

    private static bool IsLikelyDownload(string path) => !path.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
}
