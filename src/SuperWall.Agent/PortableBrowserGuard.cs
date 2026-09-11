using System.Diagnostics;

namespace SuperWall.Agent;

public sealed class PortableBrowserGuard : IDisposable
{
    private static readonly string[] BrowserNames =
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "chromium", "librewolf"
    };

    private static readonly string[] UserWritableMarkers =
    {
        "\\Downloads\\", "\\Desktop\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Local\\Programs\\"
    };

    private Timer? _timer;

    public void Start() => _timer = new Timer(_ => Sweep(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));

    private static void Sweep()
    {
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var name = Path.GetFileNameWithoutExtension(process.ProcessName);
                if (!BrowserNames.Any(x => x.Equals(name, StringComparison.OrdinalIgnoreCase))) continue;
                if (!WindowsUserScope.IsTargetUserProcess(process)) continue;

                string? path = null;
                try { path = process.MainModule?.FileName; } catch { }
                if (string.IsNullOrWhiteSpace(path)) continue;

                if (UserWritableMarkers.Any(m => path.Contains(m, StringComparison.OrdinalIgnoreCase)))
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                }
            }
            catch { }
            finally { process.Dispose(); }
        }
    }

    public void Dispose() => _timer?.Dispose();
}
