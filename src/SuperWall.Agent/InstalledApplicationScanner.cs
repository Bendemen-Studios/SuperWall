using Microsoft.Win32;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class InstalledApplicationScanner
{
    private static readonly string[] UninstallSubKeys =
    {
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

    public static List<InstalledApplication> Scan()
    {
        var result = new Dictionary<string, InstalledApplication>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
            foreach (var subKey in UninstallSubKeys) ReadRoot(root, subKey, result);
        return result.Values.Where(x => !string.IsNullOrWhiteSpace(x.Name)).OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).Take(2000).ToList();
    }

    private static void ReadRoot(RegistryKey root, string subKey, Dictionary<string, InstalledApplication> result)
    {
        try
        {
            using var uninstall = root.OpenSubKey(subKey);
            if (uninstall is null) return;
            foreach (var name in uninstall.GetSubKeyNames())
            {
                try
                {
                    using var app = uninstall.OpenSubKey(name);
                    if (app is null) continue;
                    var displayName = (app.GetValue("DisplayName") as string)?.Trim() ?? "";
                    if (string.IsNullOrWhiteSpace(displayName)) continue;
                    if (Convert.ToBoolean(app.GetValue("SystemComponent") ?? 0)) continue;
                    var version = ((app.GetValue("DisplayVersion") as string) ?? "").Trim();
                    var publisher = ((app.GetValue("Publisher") as string) ?? "").Trim();
                    var path = ((app.GetValue("InstallLocation") as string) ?? "").Trim();
                    var icon = ((app.GetValue("DisplayIcon") as string) ?? "").Trim();
                    if (string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(icon)) path = icon.Split(',')[0].Trim().Trim('"');
                    path = NormalizePath(path);
                    var key = $"{displayName}\0{version}\0{publisher}";
                    result.TryAdd(key, new InstalledApplication { Name = displayName, Version = version, Publisher = publisher, Path = path });
                }
                catch { }
            }
        }
        catch { }
    }

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        value = Environment.ExpandEnvironmentVariables(value.Trim());
        if (value.StartsWith("@", StringComparison.Ordinal)) return "";
        return value.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }
}
