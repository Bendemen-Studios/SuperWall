using System.Diagnostics;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class AppGuard : IDisposable
{
    private readonly object _gate = new();
    private Timer? _timer;
    private SuperWallPolicy _policy = new();
    private int _sweeping;

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
        if (Interlocked.Exchange(ref _sweeping, 1) != 0) return;
        try
        {
            SuperWallPolicy policy;
            lock (_gate) policy = _policy;
            if (!policy.AppBlockingEnabled) return;

            var allowedNames = new HashSet<string>((policy.AllowedApplications ?? new()).Select(NormalizeName), StringComparer.OrdinalIgnoreCase);
            var allowedPaths = NormalizePaths(policy.AllowedApplicationPaths);
            var blockedNames = new HashSet<string>((policy.BlockedApplications ?? new()).Select(NormalizeName), StringComparer.OrdinalIgnoreCase);
            var blockedPaths = NormalizePaths(policy.BlockedApplicationPaths);
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
                        path = NormalizePath(path);

                        if (allowedNames.Contains(name) || MatchesAnyPath(path, allowedPaths)) continue;

                        var nameBlocked = blockedNames.Contains(name);
                        var pathBlocked = MatchesAnyPath(path, blockedPaths);
                        if (!nameBlocked && !pathBlocked) continue;

                        try { process.Kill(entireProcessTree: true); } catch { }
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
            }
            catch { }
        }
        finally
        {
            Volatile.Write(ref _sweeping, 0);
        }
    }

    private static string[] NormalizePaths(IEnumerable<string>? paths)
        => (paths ?? Array.Empty<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(NormalizePath)
            .Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static bool MatchesAnyPath(string processPath, IEnumerable<string> prefixes)
    {
        if (string.IsNullOrWhiteSpace(processPath)) return false;
        foreach (var prefix in prefixes)
        {
            if (processPath.Equals(prefix, StringComparison.OrdinalIgnoreCase)) return true;
            if (processPath.StartsWith(prefix + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
            if (Path.DirectorySeparatorChar != Path.AltDirectorySeparatorChar && processPath.StartsWith(prefix + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string NormalizeName(string value)
        => Path.GetFileNameWithoutExtension(value ?? string.Empty).Trim();

    private static string NormalizePath(string value)
        => Environment.ExpandEnvironmentVariables(value ?? string.Empty)
            .Trim()
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    public void Dispose()
    {
        lock (_gate)
        {
            _timer?.Dispose();
            _timer = null;
        }
        Volatile.Write(ref _sweeping, 0);
    }
}
