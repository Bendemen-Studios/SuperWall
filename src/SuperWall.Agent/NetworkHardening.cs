using Microsoft.Win32;

namespace SuperWall.Agent;

public static class NetworkHardening
{
    private static readonly string HostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
    private const string MarkerStart = "# SUPERWALL-START";
    private const string MarkerEnd = "# SUPERWALL-END";
    private const string FirewallRule = "SuperWall - Block external DNS";

    /// <summary>
    /// Removes enforcement created by SuperWall versions that used machine-wide
    /// hosts/firewall/DNS controls. New versions intentionally do not re-enable
    /// those controls because they would also affect the parent's account.
    /// </summary>
    public static void ClearLegacyMachineEnforcement()
    {
        if (!OperatingSystem.IsWindows()) return;
        RemoveHosts();
        RemoveDnsFirewall();
        ClearCorporateMode();
    }

    private static void RemoveHosts()
    {
        try
        {
            if (!File.Exists(HostsPath)) return;
            var lines = File.ReadAllLines(HostsPath).ToList();
            var start = lines.FindIndex(x => x.Trim().Equals(MarkerStart, StringComparison.Ordinal));
            var end = lines.FindIndex(start >= 0 ? start + 1 : 0, x => x.Trim().Equals(MarkerEnd, StringComparison.Ordinal));
            if (start >= 0 && end >= start)
            {
                lines.RemoveRange(start, end - start + 1);
                File.WriteAllLines(HostsPath, lines);
                FlushDnsCache();
            }
        }
        catch { }
    }

    private static void RemoveDnsFirewall()
    {
        Run("netsh", $"advfirewall firewall delete rule name=\"{FirewallRule}\"");
        Run("netsh", $"advfirewall firewall delete rule name=\"{FirewallRule} TCP\"");
    }

    private static void ClearCorporateMode()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation", true);
            if (key?.GetValue("CorporateMode") is int value && value == 1)
                key.DeleteValue("CorporateMode", false);
        }
        catch { }
    }

    private static void FlushDnsCache() => Run("ipconfig", "/flushdns");

    private static void Run(string file, string arguments)
    {
        try
        {
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
