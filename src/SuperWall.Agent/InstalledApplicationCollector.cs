using Microsoft.Win32;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public static class InstalledApplicationCollector
{
    private static readonly string[] UninstallRoots =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

    public static List<InstalledApplication> Collect()
    {
        var result = new Dictionary<string, InstalledApplication>(StringComparer.OrdinalIgnoreCase);
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                foreach (var root in UninstallRoots) ReadRoot(baseKey, root, result);
            }
            catch { }
        }

        return result.Values
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(2000)
            .ToList();
    }

    private static void ReadRoot(RegistryKey baseKey, string root, Dictionary<string, InstalledApplication> result)
    {
        using var key = baseKey.OpenSubKey(root);
        if (key is null) return;
        foreach (var name in key.GetSubKeyNames())
        {
            try
            {
                using var app = key.OpenSubKey(name);
                if (app is null) continue;
                var displayName = app.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(displayName)) continue;
                var path = app.GetValue("DisplayIcon") as string ?? app.GetValue("InstallLocation") as string ?? "";
                path = path.Trim().Trim('"');
                var item = new InstalledApplication
                {
                    Name = displayName.Trim(),
                    Version = (app.GetValue("DisplayVersion") as string ?? "").Trim(),
                    Publisher = (app.GetValue("Publisher") as string ?? "").Trim(),
                    Path = path
                };
                var id = $"{item.Name}|{item.Version}|{item.Publisher}";
                result.TryAdd(id, item);
            }
            catch { }
        }
    }
}
