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
        SetLocalMachine(path, "ProxyMode", "fixed_servers");
        SetLocalMachine(path, "ProxyServer", "127.0.0.1:18580");
        SetLocalMachine(path, "DnsOverHttpsMode", "off");
        SetLocalMachine(path, "QuicAllowed", 0);
        SetLocalMachine(path, "BackgroundModeEnabled", 0);
        if (policy.DownloadsBlocked) SetLocalMachine(path, "DownloadRestrictions", 3);
        else DeleteValue(path, "DownloadRestrictions");
    }

    private static void ApplyFirefox(SuperWallPolicy policy)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Mozilla Firefox", "distribution");
            Directory.CreateDirectory(dir);
            var json = "{\"policies\":{\"Preferences\":{\"network.trr.mode\":{\"Value\":5},\"network.http.http3.enabled\":{\"Value\":false}},\"Proxy\":{\"Mode\":\"manual\",\"HTTPProxy\":\"127.0.0.1\",\"HTTPPort\":18580,\"SSLProxy\":\"127.0.0.1\",\"SSLProxyPort\":18580,\"UseHTTPProxyForAllProtocols\":true,\"Passthrough\":\"<local>\"}}}";
            File.WriteAllText(Path.Combine(dir, "policies.json"), json);
        }
        catch { }
    }

    private static void SetLocalMachine(string path, string name, object value)
    {
        try { using var key = Registry.LocalMachine.CreateSubKey(path); key?.SetValue(name, value); } catch { }
    }

    private static void DeleteValue(string path, string name)
    {
        try { Registry.LocalMachine.OpenSubKey(path, true)?.DeleteValue(name, false); } catch { }
    }
}
