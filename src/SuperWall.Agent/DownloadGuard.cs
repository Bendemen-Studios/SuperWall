using SuperWall.Contracts;
using Microsoft.Win32;

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

        var downloads = FindTargetDownloadDirectory();
        if (downloads is null) return;

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

    private static string? FindTargetDownloadDirectory()
    {
        var profile = WindowsUserScope.ProfilePath();
        if (string.IsNullOrWhiteSpace(profile)) return null;
        var downloads = Path.Combine(profile, "Downloads");
        return Directory.Exists(downloads) ? downloads : null;
    }

    private static bool IsLikelyDownload(string path) => !path.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
        && !path.EndsWith(".download", StringComparison.OrdinalIgnoreCase);

    private static void DeleteState()
    {
        try { File.Delete(Path.Combine(StateDir, "download-unlocked.json")); } catch { }
    }
}
