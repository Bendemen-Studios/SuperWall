using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class DownloadGuard
{
    private static readonly object Gate = new();
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    private static Timer? _timer;
    private static FileSystemWatcher? _watcher;
    private static bool _enabled;

    public static void SetEnabled(bool enabled, SuperWallPolicy policy)
    {
        lock (Gate)
        {
            _enabled = enabled;
            _timer?.Dispose();
            _timer = null;
            _watcher?.Dispose();
            _watcher = null;

            if (!enabled)
            {
                DeleteState();
                return;
            }

            var downloads = FindTargetDownloadDirectory();
            if (!string.IsNullOrWhiteSpace(downloads))
            {
                try
                {
                    _watcher = new FileSystemWatcher(downloads)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                        Filter = "*.*",
                        EnableRaisingEvents = true
                    };
                    _watcher.Created += (_, e) => QuarantineWhenReady(e.FullPath);
                    _watcher.Renamed += (_, e) => QuarantineWhenReady(e.FullPath);
                }
                catch
                {
                    _watcher?.Dispose();
                    _watcher = null;
                }
            }

            _timer = new Timer(_ => Sweep(), null, TimeSpan.Zero, TimeSpan.FromSeconds(1));
        }
    }

    public static bool IsEnabled()
    {
        lock (Gate) return _enabled;
    }

    private static void Sweep()
    {
        if (!IsEnabled()) return;

        try
        {
            var downloads = FindTargetDownloadDirectory();
            if (string.IsNullOrWhiteSpace(downloads)) return;

            foreach (var file in Directory.EnumerateFiles(downloads, "*", SearchOption.AllDirectories))
                QuarantineWhenReady(file);
        }
        catch { }
    }

    private static void QuarantineWhenReady(string path)
    {
        if (!IsEnabled() || !IsLikelyDownload(path)) return;

        _ = Task.Run(async () =>
        {
            for (var attempt = 0; attempt < 8 && IsEnabled(); attempt++)
            {
                try
                {
                    if (!File.Exists(path)) return;
                    var quarantine = Path.Combine(StateDir, "Quarantine");
                    Directory.CreateDirectory(quarantine);
                    var target = Path.Combine(quarantine, Path.GetFileName(path));
                    if (File.Exists(target))
                        target = Path.Combine(quarantine, $"{Guid.NewGuid():N}-{Path.GetFileName(path)}");

                    File.Move(path, target);
                    return;
                }
                catch
                {
                    try { await Task.Delay(250); } catch { return; }
                }
            }
        });
    }

    private static string? FindTargetDownloadDirectory()
    {
        var profile = WindowsUserScope.ProfilePath();
        if (string.IsNullOrWhiteSpace(profile)) return null;
        var downloads = Path.Combine(profile, "Downloads");
        return Directory.Exists(downloads) ? downloads : null;
    }

    private static bool IsLikelyDownload(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;
        var name = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(name)) return false;

        return !name.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
            && !name.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
            && !name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
            && !name.EndsWith(".download", StringComparison.OrdinalIgnoreCase);
    }

    private static void DeleteState()
    {
        try { File.Delete(Path.Combine(StateDir, "download-unlocked.json")); } catch { }
    }
}
