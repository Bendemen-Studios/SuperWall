using Microsoft.Win32;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class BrowserPolicy
{
    public static void Apply(SuperWallPolicy policy)
    {
        if (!OperatingSystem.IsWindows()) return;
        ApplyChromium(@"SOFTWARE\Policies\Microsoft\Edge", policy);
        ApplyChromium(@"SOFTWARE\Policies\Google\Chrome", policy);
        ApplyFirefox(policy);
    }

    private static void ApplyChromium(string path, SuperWallPolicy policy)
    {
        Set(path, "ProxyMode", "fixed_servers");
        Set(path, "ProxyServer", "127.0.0.1:18580");
        Set(path, "DnsOverHttpsMode", "off");
        Set(path, "QuicAllowed", 0);
        Set(path, "BackgroundModeEnabled", 0);
        Set(path, "ExtensionInstallBlocklist", new[] { "*" });

        // Explicitly set 0 when downloads are allowed. Deleting the policy is
        // not enough on every Chromium/Windows policy refresh path and could
        // leave a previously enforced DownloadRestrictions=3 active.
        Set(path, "DownloadRestrictions", policy.DownloadsBlocked ? 3 : 0);

        if (policy.UrlBlockingEnabled)
        {
            var blocked = policy.BlockedDomains
                .Where(IsValidDomain)
                .SelectMany(d => new[] { $"*://{d}/*", $"*://*.{d}/*" })
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (blocked.Length > 0) Set(path, "URLBlocklist", blocked);
            else Delete(path, "URLBlocklist");
        }
        else
        {
            Delete(path, "URLBlocklist");
        }
    }

    private static void ApplyFirefox(SuperWallPolicy policy)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Mozilla Firefox", "distribution");
            Directory.CreateDirectory(dir);
            var json = "{\"policies\":{\"DisableTelemetry\":true,\"Preferences\":{\"network.trr.mode\":{\"Value\":5},\"network.http.http3.enabled\":{\"Value\":false}},\"Proxy\":{\"Mode\":\"manual\",\"HTTPProxy\":\"127.0.0.1\",\"HTTPPort\":18580,\"SSLProxy\":\"127.0.0.1\",\"SSLProxyPort\":18580,\"UseHTTPProxyForAllProtocols\":true,\"Passthrough\":\"<local>\"}}}";
            File.WriteAllText(Path.Combine(dir, "policies.json"), json);
        }
        catch { }
    }

    private static void Set(string path, string name, object value)
    {
        try { using var key = Registry.LocalMachine.CreateSubKey(path); key?.SetValue(name, value); } catch { }
    }

    private static void Delete(string path, string name)
    {
        try { Registry.LocalMachine.OpenSubKey(path, true)?.DeleteValue(name, false); } catch { }
    }

    private static bool IsValidDomain(string d) =>
        d.Length <= 253 && d.Contains('.') && d.All(c => char.IsLetterOrDigit(c) || c is '.' or '-');
}
