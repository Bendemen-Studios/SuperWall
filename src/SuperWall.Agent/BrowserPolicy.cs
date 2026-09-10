using Microsoft.Win32;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class BrowserPolicy
{
    public static void Apply(SuperWallPolicy policy)
    {
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
        if (policy.DownloadsBlocked) Set(path, "DownloadRestrictions", 3);
        else Delete(path, "DownloadRestrictions");
        if (policy.LockBrowserInstallation) Set(path, "URLBlocklist", new[] { "file:///C:/Users/*/Downloads/*" });
    }

    private static void ApplyFirefox(SuperWallPolicy policy)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Mozilla Firefox", "distribution");
            Directory.CreateDirectory(dir);
            var download = policy.DownloadsBlocked ? ",\"DownloadRestrictions\":{\"Default\":true}" : "";
            var json = "{\"policies\":{\"DisableAppUpdate\":false,\"DisableTelemetry\":true,\"Preferences\":{\"network.trr.mode\":{\"Value\":5},\"network.http.http3.enabled\":{\"Value\":false}},\"Proxy\":{\"Mode\":\"manual\",\"HTTPProxy\":\"127.0.0.1\",\"HTTPPort\":18580,\"SSLProxy\":\"127.0.0.1\",\"SSLProxyPort\":18580,\"UseHTTPProxyForAllProtocols\":true,\"Passthrough\":\"<local>\"}" + download + "}}";
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
}
