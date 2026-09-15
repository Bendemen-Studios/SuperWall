using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SuperWall.Agent;

/// <summary>
/// Removes SuperWall enforcement without removing unrelated Chrome/Edge policy.
/// Must be invoked from an elevated administrator process.
/// </summary>
public static class SuperWallUninstaller
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    private static readonly string[] ChromiumPolicyPaths =
    {
        @"SOFTWARE\Policies\Microsoft\Edge",
        @"SOFTWARE\Policies\Google\Chrome",
        @"SOFTWARE\Policies\BraveSoftware\Brave-Browser",
        @"SOFTWARE\Policies\Vivaldi",
        @"SOFTWARE\Policies\Opera Software\Opera Stable"
    };

    private static readonly string[] SuperWallPolicyValues =
    {
        "ProxyMode", "ProxyServer", "DnsOverHttpsMode", "QuicAllowed",
        "BackgroundModeEnabled", "ExtensionInstallBlocklist", "ProxyBypassList",
        "DownloadRestrictions"
    };

    private const string ServiceName = "SuperWallAgent";
    private const int HKeyUsers = unchecked((int)0x80000003);

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

    public static int Run()
    {
        if (!OperatingSystem.IsWindows()) return 1;
        if (!IsAdministrator()) return 740; // ERROR_ELEVATION_REQUIRED

        try
        {
            StopAndDeleteService();
            ClearAllBrowserPolicies();
            RemoveSuperWallScheduledTasks();
            RunGpUpdate();
            ScheduleSelfDelete();
            return 0;
        }
        catch (Exception ex)
        {
            AgentLogger.Error("SuperWall uninstall failed.", ex);
            return 1;
        }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void StopAndDeleteService()
    {
        RunProcess("sc.exe", $"stop {ServiceName}", 10000);
        RunProcess("sc.exe", $"delete {ServiceName}", 10000);
    }

    private static void ClearAllBrowserPolicies()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            foreach (var path in ChromiumPolicyPaths)
                ClearPolicyKey(machine, path);
        }

        // Clean the administrator's current user hive too.
        foreach (var path in ChromiumPolicyPaths)
            ClearPolicyKey(Registry.CurrentUser, path);

        // The service targets a child account, but an older SuperWall version may
        // have written policy to the wrong/admin account. Clean every local profile
        // hive so uninstall reliably removes that stale enforcement everywhere.
        foreach (var sid in FindLocalProfileSids())
            ClearUserHive(sid);
    }

    private static void ClearPolicyKey(RegistryKey root, string path)
    {
        try
        {
            using var key = root.OpenSubKey(path, writable: true);
            if (key is null) return;

            foreach (var value in SuperWallPolicyValues)
            {
                try { key.DeleteValue(value, throwOnMissingValue: false); } catch { }
            }

            try { key.DeleteSubKeyTree("URLBlocklist", throwOnMissingSubKey: false); } catch { }
        }
        catch { }
    }

    private static IEnumerable<string> FindLocalProfileSids()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList is null) return result;

            foreach (var sid in profileList.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var identity = new SecurityIdentifier(sid);
                    result.Add(identity.Value);
                }
                catch { }
            }
        }
        catch { }
        return result;
    }

    private static void ClearUserHive(string sid)
    {
        var loadedByUs = false;
        try
        {
            using (Registry.Users.OpenSubKey(sid)) { }
            if (Registry.Users.OpenSubKey(sid) is null)
            {
                var profile = GetProfilePath(sid);
                var hiveFile = string.IsNullOrWhiteSpace(profile) ? null : Path.Combine(profile, "NTUSER.DAT");
                if (!string.IsNullOrWhiteSpace(hiveFile) && File.Exists(hiveFile))
                    loadedByUs = RegLoadKey(new IntPtr(HKeyUsers), sid, hiveFile) == 0;
            }

            using var hive = Registry.Users.OpenSubKey(sid, writable: true);
            if (hive is null) return;
            foreach (var path in ChromiumPolicyPaths)
                ClearPolicyKey(hive, path);
        }
        catch { }
        finally
        {
            if (loadedByUs)
            {
                try { RegUnLoadKey(new IntPtr(HKeyUsers), sid); } catch { }
            }
        }
    }

    private static string? GetProfilePath(string sid)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
            var path = key?.GetValue("ProfileImagePath") as string;
            return string.IsNullOrWhiteSpace(path) ? null : Environment.ExpandEnvironmentVariables(path);
        }
        catch { return null; }
    }

    private static void RemoveSuperWallScheduledTasks()
    {
        // Safe even when the task does not exist. This covers older development builds
        // that may have registered an updater task under either of these names.
        foreach (var task in new[] { "SuperWall", "SuperWallUpdater", "SuperWall Agent" })
            RunProcess("schtasks.exe", $"/Delete /TN \"{task}\" /F", 5000);
    }

    private static void RunGpUpdate()
    {
        RunProcess("gpupdate.exe", "/target:computer /force", 30000);
        RunProcess("gpupdate.exe", "/target:user /force", 30000);
    }

    private static void ScheduleSelfDelete()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe)) return;

        var tempScript = Path.Combine(Path.GetTempPath(), $"superwall-uninstall-{Guid.NewGuid():N}.cmd");
        var appDir = Path.GetDirectoryName(exe);
        var lines = new List<string>
        {
            "@echo off",
            "timeout /t 2 /nobreak >nul",
            $"del /f /q \"{exe}\" >nul 2>&1",
            $"if exist \"{exe}\" goto retry",
            $"rmdir /s /q \"{appDir}\" >nul 2>&1",
            $"rmdir /s /q \"{StateDir}\" >nul 2>&1",
            "del /f /q \"%~f0\" >nul 2>&1",
            "exit /b 0",
            ":retry",
            "timeout /t 2 /nobreak >nul",
            "goto retry"
        };
        File.WriteAllLines(tempScript, lines);
        Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{tempScript}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }

    private static int RunProcess(string fileName, string arguments, int timeoutMs)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            if (process is null) return -1;
            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(true); } catch { }
                return -2;
            }
            return process.ExitCode;
        }
        catch { return -1; }
    }
}
