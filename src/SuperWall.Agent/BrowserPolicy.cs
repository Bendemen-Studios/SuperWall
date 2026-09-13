using Microsoft.Win32;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class BrowserPolicy
{
    private static readonly string[] ChromiumPolicyPaths =
    {
        @"SOFTWARE\Policies\Microsoft\Edge",
        @"SOFTWARE\Policies\Google\Chrome",
        @"SOFTWARE\Policies\BraveSoftware\Brave-Browser",
        @"SOFTWARE\Policies\Vivaldi",
        @"SOFTWARE\Policies\Opera Software\Opera Stable"
    };

    public static void Apply(SuperWallPolicy policy)
    {
        Apply(policy, DownloadGuard.IsTemporarilyUnlocked());
    }

    public static void Apply(SuperWallPolicy policy, bool downloadsUnlocked)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            foreach (var path in ChromiumPolicyPaths)
                ApplyChromium(path, policy, downloadsUnlocked);
        }
        finally
        {
            WindowsUserScope.UnloadTargetHiveIfLoadedByUs();
        }
    }

    public static void ClearEnforcement()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            foreach (var path in ChromiumPolicyPaths)
                ClearChromium(path);
        }
        finally
        {
            WindowsUserScope.UnloadTargetHiveIfLoadedByUs();
        }
    }

    private static void ApplyChromium(string path, SuperWallPolicy policy, bool downloadsUnlocked)
    {
        using var key = WindowsUserScope.OpenUserPolicyKey(path, true);
        if (key is null) return;
        try
        {
            if (policy.UrlBlockingEnabled)
            {
                key.SetValue("ProxyMode", "fixed_servers");
                key.SetValue("ProxyServer", "127.0.0.1:18580");
                key.SetValue("DnsOverHttpsMode", "off");
                key.SetValue("QuicAllowed", 0, RegistryValueKind.DWord);
                key.SetValue("BackgroundModeEnabled", 0, RegistryValueKind.DWord);
                key.SetValue("ExtensionInstallBlocklist", new[] { "*" }, RegistryValueKind.MultiString);
                key.SetValue("ProxyBypassList", new[] { "<local>" }, RegistryValueKind.MultiString);
                DeleteValue(key, "URLBlocklist");
                DeleteSubKeyTree(key, "URLBlocklist");

                var blocked = PolicyRules.GetBlockedDomains(policy)
                    .SelectMany(d => new[] { $"*://{d}/*", $"*://*.{d}/*" })
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                if (blocked.Length > 0)
                {
                    using var list = key.CreateSubKey("URLBlocklist", true);
                    for (var i = 0; i < blocked.Length; i++) list.SetValue((i + 1).ToString(), blocked[i], RegistryValueKind.String);
                }
            }
            else
            {
                DeleteValue(key, "ProxyMode");
                DeleteValue(key, "ProxyServer");
                DeleteValue(key, "DnsOverHttpsMode");
                DeleteValue(key, "QuicAllowed");
                DeleteValue(key, "BackgroundModeEnabled");
                DeleteValue(key, "ExtensionInstallBlocklist");
                DeleteValue(key, "ProxyBypassList");
                DeleteValue(key, "URLBlocklist");
                DeleteSubKeyTree(key, "URLBlocklist");
            }

            key.SetValue("DownloadRestrictions", policy.DownloadsBlocked && !downloadsUnlocked ? 3 : 0, RegistryValueKind.DWord);
        }
        catch { }
    }

    private static void ClearChromium(string path)
    {
        using var key = WindowsUserScope.OpenUserPolicyKey(path, true);
        if (key is null) return;
        DeleteValue(key, "ProxyMode"); DeleteValue(key, "ProxyServer"); DeleteValue(key, "DnsOverHttpsMode");
        DeleteValue(key, "QuicAllowed"); DeleteValue(key, "BackgroundModeEnabled"); DeleteValue(key, "ExtensionInstallBlocklist");
        DeleteValue(key, "ProxyBypassList"); DeleteValue(key, "DownloadRestrictions"); DeleteValue(key, "URLBlocklist");
        DeleteSubKeyTree(key, "URLBlocklist");
    }

    private static void DeleteValue(RegistryKey key, string name) { try { key.DeleteValue(name, false); } catch { } }
    private static void DeleteSubKeyTree(RegistryKey key, string name) { try { key.DeleteSubKeyTree(name, false); } catch { } }
}
