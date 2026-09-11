using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class DownloadGuard
{
    private static Timer? _timer;
    private static bool _enabled;
    private static readonly object Gate = new();
    private static readonly string StateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    public static void SetEnabled(bool enabled, SuperWallPolicy policy)
    {
        lock (Gate)
        {
            _enabled = enabled;
        }

        _timer?.Dispose();
        _timer = enabled ? new Timer(_ => Sweep(policy), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2)) : null;
        if (!enabled) DeleteState();
    }

    public static bool IsEnabled()
    {
        lock (Gate) return _enabled;
    }

    private static void Sweep(SuperWallPolicy policy)
    {
        if (!IsEnabled()) return;

        BrowserPolicy.Apply(policy);
        DeleteState();

        foreach (var downloads in FindDownloadDirectories())
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(downloads).Where(IsLikelyDownload))
                {
                    // The centrally managed Kids installer must remain downloadable so
                    // an existing client can be upgraded. All other downloads are still
                    // quarantined while download blocking is enabled.
                    if (IsSuperWallInstaller(file)) continue;

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

    private static bool IsSuperWallInstaller(string path)
    {
        var name = Path.GetFileName(path);
        return name.StartsWith("SuperWall-Kids-Setup-", StringComparison.OrdinalIgnoreCase)
            && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
    }

    private static void DeleteState()
    {
        try { File.Delete(Path.Combine(StateDir, "download-unlocked.json")); } catch { }
    }
}
