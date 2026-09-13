using System.Diagnostics;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class AppGuard : IDisposable
{
    private readonly object _gate = new();
    private Timer? _timer;
    private SuperWallPolicy _policy = new();

    public void Apply(SuperWallPolicy policy)
    {
        lock (_gate)
        {
            _policy = policy;
            if (!policy.AppBlockingEnabled || ((policy.BlockedApplications?.Count ?? 0) == 0 && (policy.BlockedApplicationPaths?.Count ?? 0) == 0))
            {
                _timer?.Dispose();
                _timer = null;
                return;
            }

            _timer ??= new Timer(_ => Sweep(), null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
        }
    }

    private void Sweep()
    {
        SuperWallPolicy policy;
        lock (_gate) policy = _policy;
        if (!policy.AppBlockingEnabled) return;

        var blockedNames = new HashSet<string>((policy.BlockedApplications ?? new()).Select(NormalizeName), StringComparer.OrdinalIgnoreCase);
        var blockedPaths = (policy.BlockedApplicationPaths ?? new()).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
        if (blockedNames.Count == 0 && blockedPaths.Length == 0) return;

        try
        {
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (!WindowsUserScope.IsTargetUserProcess(process)) continue;
                    var name = NormalizeName(process.ProcessName);
                    var path = string.Empty;
                    try { path = process.MainModule?.FileName ?? string.Empty; } catch { }

                    var nameBlocked = blockedNames.Contains(name);
                    var pathBlocked = blockedPaths.Any(p => !string.IsNullOrWhiteSpace(path) && path.StartsWith(Environment.ExpandEnvironmentVariables(p.Trim()), StringComparison.OrdinalIgnoreCase));
                    if (!nameBlocked && !pathBlocked) continue;

                    try { process.Kill(entireProcessTree: true); } catch { }
                }
                catch { }
                finally { process.Dispose(); }
            }
        }
        catch { }
    }

    private static string NormalizeName(string value)
    {
        value = Path.GetFileNameWithoutExtension(value ?? string.Empty).Trim();
        return value;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _timer?.Dispose();
            _timer = null;
        }
    }
}
