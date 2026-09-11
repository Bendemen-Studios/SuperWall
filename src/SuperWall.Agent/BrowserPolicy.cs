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
        // Firefox's enterprise distribution policy is machine-wide. Do not
        // write it here because SuperWall must not affect the parent's account.
    }

    public static void ClearEnforcement()
    {
        if (!OperatingSystem.IsWindows()) return;
        ClearChromium(@"SOFTWARE\Policies\Microsoft\Edge");
        ClearChromium(@"SOFTWARE\Policies\Google\Chrome");
    }

    private static void ApplyChromium(string path, SuperWallPolicy policy)
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

                // Chromium/Edge expect URLBlocklist as a registry subkey with
                // numbered REG_SZ values (1, 2, 3, ...), not as a MultiString
                // value on the parent key.
                DeleteValue(key, "URLBlocklist");
                DeleteSubKeyTree(key, "URLBlocklist");
                var blocked = policy.BlockedDomains
                    .Where(IsValidDomain)
                    .SelectMany(d => new[] { d, $"*.{d}" })
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                if (blocked.Length > 0)
                {
                    using var list = key.CreateSubKey("URLBlocklist", true);
                    for (var i = 0; i < blocked.Length; i++)
                        list.SetValue((i + 1).ToString(), blocked[i], RegistryValueKind.String);
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
                DeleteValue(key, "URLBlocklist");
                DeleteSubKeyTree(key, "URLBlocklist");
            }

            key.SetValue("DownloadRestrictions", policy.DownloadsBlocked ? 3 : 0, RegistryValueKind.DWord);
        }
        catch { }
    }

    private static void ClearChromium(string path)
    {
        using var key = WindowsUserScope.OpenUserPolicyKey(path, true);
        if (key is null) return;
        DeleteValue(key, "ProxyMode");
        DeleteValue(key, "ProxyServer");
        DeleteValue(key, "DnsOverHttpsMode");
        DeleteValue(key, "QuicAllowed");
        DeleteValue(key, "BackgroundModeEnabled");
        DeleteValue(key, "ExtensionInstallBlocklist");
        DeleteValue(key, "DownloadRestrictions");
        DeleteValue(key, "URLBlocklist");
        DeleteSubKeyTree(key, "URLBlocklist");
    }

    private static void DeleteValue(RegistryKey key, string name)
    {
        try { key.DeleteValue(name, false); } catch { }
    }

    private static void DeleteSubKeyTree(RegistryKey key, string name)
    {
        try { key.DeleteSubKeyTree(name, false); } catch { }
    }

    private static bool IsValidDomain(string d) =>
        !string.IsNullOrWhiteSpace(d) && d.Length <= 253 && d.Contains('.') &&
        d.All(c => char.IsLetterOrDigit(c) || c is '.' or '-');
}
