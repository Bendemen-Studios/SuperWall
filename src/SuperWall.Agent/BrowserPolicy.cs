using Microsoft.Win32;

namespace SuperWall.Agent;

public static class BrowserPolicy
{
    public static void Apply(bool downloadsBlocked)
    {
        // Force Chromium browsers through the local SuperWall proxy and disable DoH bypasses.
        SetLocalMachine("SOFTWARE\\Policies\\Microsoft\\Edge", "ProxyMode", "fixed_servers");
        SetLocalMachine("SOFTWARE\\Policies\\Microsoft\\Edge", "ProxyServer", "127.0.0.1:18580");
        SetLocalMachine("SOFTWARE\\Policies\\Microsoft\\Edge", "DnsOverHttpsMode", "off");
        SetLocalMachine("SOFTWARE\\Policies\\Google\\Chrome", "ProxyMode", "fixed_servers");
        SetLocalMachine("SOFTWARE\\Policies\\Google\\Chrome", "ProxyServer", "127.0.0.1:18580");
        SetLocalMachine("SOFTWARE\\Policies\\Google\\Chrome", "DnsOverHttpsMode", "off");
        if (downloadsBlocked)
        {
            SetLocalMachine("SOFTWARE\\Policies\\Microsoft\\Edge", "DownloadRestrictions", 3);
            SetLocalMachine("SOFTWARE\\Policies\\Google\\Chrome", "DownloadRestrictions", 3);
        }
        else
        {
            DeleteValue("SOFTWARE\\Policies\\Microsoft\\Edge", "DownloadRestrictions");
            DeleteValue("SOFTWARE\\Policies\\Google\\Chrome", "DownloadRestrictions");
        }

        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Mozilla Firefox", "distribution");
            Directory.CreateDirectory(dir);
            var json = "{\"policies\":{\"Preferences\":{\"network.trr.mode\":{\"Value\":5}},\"Proxy\":{\"Mode\":\"manual\",\"HTTPProxy\":\"127.0.0.1\",\"HTTPPort\":18580,\"UseHTTPProxyForAllProtocols\":true,\"Passthrough\":\"<local>\"}}}";
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
