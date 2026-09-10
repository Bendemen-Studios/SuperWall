using Microsoft.Win32;

namespace SuperWall.Agent;

public static class NetworkHardening
{
    private const string StateDirName = "SuperWall";
    private static readonly string HostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
    private const string MarkerStart = "# SUPERWALL-START";
    private const string MarkerEnd = "# SUPERWALL-END";
    private const string FirewallRule = "SuperWall - Block external DNS";

    public static void Apply(IEnumerable<string> domains, bool enabled)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (enabled)
        {
            ApplyHosts(domains);
            DisableDoHAndQuic();
            ApplyDnsFirewall();
        }
        else
        {
            RemoveHosts();
            RemoveDnsFirewall();
        }
    }

    private static void ApplyHosts(IEnumerable<string> domains)
    {
        try
        {
            var lines = File.Exists(HostsPath) ? File.ReadAllLines(HostsPath).ToList() : new List<string>();
            var start = lines.FindIndex(x => x.Trim().Equals(MarkerStart, StringComparison.Ordinal));
            var end = lines.FindIndex(start >= 0 ? start + 1 : 0, x => x.Trim().Equals(MarkerEnd, StringComparison.Ordinal));
            if (start >= 0 && end >= start) lines.RemoveRange(start, end - start + 1);
            var block = new List<string> { MarkerStart };
            foreach (var domain in domains.Where(IsValidDomain).Select(x => x.Trim().TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                block.Add($"0.0.0.0 {domain}");
                block.Add($"0.0.0.0 www.{domain}");
                block.Add($":: {domain}");
                block.Add($":: www.{domain}");
            }
            block.Add(MarkerEnd);
            lines.AddRange(block);
            File.WriteAllLines(HostsPath, lines);
            FlushDnsCache();
        }
        catch { }
    }

    private static void RemoveHosts()
    {
        try
        {
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

    private static void ApplyDnsFirewall()
    {
        Run("netsh", $"advfirewall firewall delete rule name=\"{FirewallRule}\"");
        Run("netsh", $"advfirewall firewall add rule name=\"{FirewallRule}\" dir=out action=block protocol=UDP remoteport=53,853 profile=any");
        Run("netsh", $"advfirewall firewall add rule name=\"{FirewallRule} TCP\" dir=out action=block protocol=TCP remoteport=53,853 profile=any");
    }

    private static void RemoveDnsFirewall()
    {
        Run("netsh", $"advfirewall firewall delete rule name=\"{FirewallRule}\"");
        Run("netsh", $"advfirewall firewall delete rule name=\"{FirewallRule} TCP\"");
    }

    private static void DisableDoHAndQuic()
    {
        try
        {
            using var services = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation");
            services?.SetValue("CorporateMode", 1, RegistryValueKind.DWord);
        }
        catch { }
    }

    private static void FlushDnsCache() => Run("ipconfig", "/flushdns");

    private static bool IsValidDomain(string value) => value.Length <= 253 && value.Contains('.') && value.All(c => char.IsLetterOrDigit(c) || c is '.' or '-');

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
