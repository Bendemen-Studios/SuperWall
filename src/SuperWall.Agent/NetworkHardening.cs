using Microsoft.Win32;

namespace SuperWall.Agent;

public static class NetworkHardening
{
    private const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";
    private const string Start = "# SUPERWALL-START";
    private const string End = "# SUPERWALL-END";
    private const string DnsRuleUdp = "SuperWall - Block external DNS";
    private const string DnsRuleTcp = "SuperWall - Block external DNS TCP";

    public static void Apply(IEnumerable<string> domains, bool enabled)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (enabled) { ApplyHosts(domains); ApplyDnsFirewall(); }
        else { RemoveHosts(); RemoveDnsFirewall(); }
        DisableDoHPolicy();
    }

    private static void ApplyHosts(IEnumerable<string> domains)
    {
        try
        {
            var lines = File.Exists(HostsPath) ? File.ReadAllLines(HostsPath).ToList() : new List<string>();
            var start = lines.FindIndex(x => x.Trim().Equals(Start, StringComparison.Ordinal));
            var end = start >= 0 ? lines.FindIndex(start + 1, x => x.Trim().Equals(End, StringComparison.Ordinal)) : -1;
            if (start >= 0 && end >= start) lines.RemoveRange(start, end - start + 1);
            lines.Add(Start);
            foreach (var d in domains.Where(IsValidDomain).Select(x => x.Trim().TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                lines.Add($"0.0.0.0 {d}"); lines.Add($"0.0.0.0 www.{d}"); lines.Add($":: {d}"); lines.Add($":: www.{d}");
            }
            lines.Add(End);
            File.WriteAllLines(HostsPath, lines);
            Run("ipconfig", "/flushdns");
        }
        catch { }
    }

    private static void RemoveHosts()
    {
        try
        {
            var lines = File.ReadAllLines(HostsPath).ToList();
            var start = lines.FindIndex(x => x.Trim().Equals(Start, StringComparison.Ordinal));
            var end = start >= 0 ? lines.FindIndex(start + 1, x => x.Trim().Equals(End, StringComparison.Ordinal)) : -1;
            if (start >= 0 && end >= start) { lines.RemoveRange(start, end - start + 1); File.WriteAllLines(HostsPath, lines); Run("ipconfig", "/flushdns"); }
        }
        catch { }
    }

    private static void ApplyDnsFirewall()
    {
        Run("netsh", $"advfirewall firewall delete rule name=\"{DnsRuleUdp}\"");
        Run("netsh", $"advfirewall firewall delete rule name=\"{DnsRuleTcp}\"");
        Run("netsh", $"advfirewall firewall add rule name=\"{DnsRuleUdp}\" dir=out action=block protocol=UDP remoteport=53,853 profile=any");
        Run("netsh", $"advfirewall firewall add rule name=\"{DnsRuleTcp}\" dir=out action=block protocol=TCP remoteport=53,853 profile=any");
    }

    private static void RemoveDnsFirewall()
    {
        Run("netsh", $"advfirewall firewall delete rule name=\"{DnsRuleUdp}\"");
        Run("netsh", $"advfirewall firewall delete rule name=\"{DnsRuleTcp}\"");
    }

    private static void DisableDoHPolicy()
    {
        try { using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Edge"); key?.SetValue("DnsOverHttpsMode", "off"); using var chrome = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Google\Chrome"); chrome?.SetValue("DnsOverHttpsMode", "off"); } catch { }
    }

    private static bool IsValidDomain(string d) => d.Length <= 253 && d.Contains('.') && d.All(c => char.IsLetterOrDigit(c) || c is '.' or '-');
    private static void Run(string file, string args) { try { using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true }); p?.WaitForExit(5000); } catch { } }
}
