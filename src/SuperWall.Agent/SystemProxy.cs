using Microsoft.Win32;

namespace SuperWall.Agent;

public static class SystemProxy
{
    private const string InternetSettings = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public static void Set(string host, int port)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettings, true);
            key?.SetValue("ProxyEnable", 1);
            key?.SetValue("ProxyServer", $"{host}:{port}");
            key?.SetValue("ProxyOverride", "<local>");
        }
        catch { }
    }

    public static void Clear()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettings, true);
            key?.SetValue("ProxyEnable", 0);
        }
        catch { }
    }
}
