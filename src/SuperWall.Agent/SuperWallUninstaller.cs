using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Principal;

namespace SuperWall.Agent;

/// <summary>
/// Administrative maintenance commands for SuperWall.
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

    private const string ServiceName = "SuperWallAgent";

    public static int Run()
    {
        if (!OperatingSystem.IsWindows()) return 1;
        if (!IsAdministrator()) return 740;

        try
        {
            StopAndDeleteService();
            ResetCurrentUserBrowserPolicies();
            ResetTargetUserBrowserPolicies();
            ResetWindowsProxy();
            ResetTargetUserProxy();
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

    public static int PrintStatus()
    {
        if (!OperatingSystem.IsWindows()) return 1;
        if (!IsAdministrator()) return 740;

        var result = RunProcess("sc.exe", $"query {ServiceName}", 5000);
        Console.WriteLine($"SuperWall Agent service exit code: {result}");
        return result == 0 ? 0 : 1;
    }

    public static bool IsAdministrator()
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

    private static void ResetCurrentUserBrowserPolicies()
    {
        var ownedValues = new[]
        {
            "ProxyMode",
            "ProxyServer",
            "DnsOverHttpsMode",
            "QuicAllowed",
            "BackgroundModeEnabled",
            "ExtensionInstallBlocklist",
            "ProxyBypassList",
            "DownloadRestrictions",
            "URLBlocklist"
        };

        foreach (var path in ChromiumPolicyPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(path, writable: true);
                if (key is null) continue;

                foreach (var value in ownedValues)
                {
                    try { key.DeleteValue(value, throwOnMissingValue: false); }
                    catch (Exception ex)
                    {
                        AgentLogger.Error($"Could not remove browser policy value {path}\\{value}.", ex);
                    }
                }

                try { key.DeleteSubKeyTree("URLBlocklist", throwOnMissingSubKey: false); }
                catch (Exception ex)
                {
                    AgentLogger.Error($"Could not remove browser URLBlocklist policy at {path}.", ex);
                }
            }
            catch (Exception ex)
            {
                AgentLogger.Error($"Could not reset current-user browser policy: {path}", ex);
            }
        }
    }

    private static void ResetTargetUserBrowserPolicies()
    {
        var ownedValues = new[]
        {
            "ProxyMode", "ProxyServer", "DnsOverHttpsMode", "QuicAllowed",
            "BackgroundModeEnabled", "ExtensionInstallBlocklist", "ProxyBypassList",
            "DownloadRestrictions", "URLBlocklist"
        };

        foreach (var path in ChromiumPolicyPaths)
        {
            try
            {
                using var key = WindowsUserScope.OpenUserPolicyKey(path, writable: true);
                if (key is null) continue;
                foreach (var value in ownedValues)
                    key.DeleteValue(value, throwOnMissingValue: false);
                key.DeleteSubKeyTree("URLBlocklist", throwOnMissingSubKey: false);
            }
            catch (Exception ex)
            {
                AgentLogger.Error($"Could not reset target-user browser policy: {path}", ex);
            }
        }

        WindowsUserScope.UnloadTargetHiveIfLoadedByUs();
    }

    private static void ResetWindowsProxy()
    {
        // Reset WinHTTP and the current Windows user's Internet Settings.
        RunProcess("netsh.exe", "winhttp reset proxy", 10000);

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                writable: true);

            if (key is not null)
            {
                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
                key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            }
        }
        catch (Exception ex)
        {
            AgentLogger.Error("Could not reset current-user Windows proxy settings.", ex);
        }
    }

    private static void ResetTargetUserProxy()
    {
        try
        {
            using var key = WindowsUserScope.OpenUserPolicyKey(
                @"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: true);
            if (key is null) return;
            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            key.DeleteValue("ProxyServer", throwOnMissingValue: false);
            key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
            key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
        }
        catch (Exception ex)
        {
            AgentLogger.Error("Could not reset target-user Windows proxy settings.", ex);
        }
        finally
        {
            WindowsUserScope.UnloadTargetHiveIfLoadedByUs();
        }
    }

    private static void RemoveSuperWallScheduledTasks()
    {
        foreach (var task in new[] { "SuperWall", "SuperWallUpdater", "SuperWall Agent" })
            RunProcess("schtasks.exe", $"/Delete /TN \"{task}\" /F", 5000);
    }

    private static void RunGpUpdate()
    {
        RunProcess("gpupdate.exe", "/target:user /force", 30000);
    }

    private static void ScheduleSelfDelete()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe)) return;

        var tempScript = Path.Combine(Path.GetTempPath(), $"superwall-uninstall-{Guid.NewGuid():N}.cmd");
        var appDir = Path.GetDirectoryName(exe);
        if (string.IsNullOrWhiteSpace(appDir)) return;

        var wrapperPath = Path.Combine(Environment.SystemDirectory, "superwall.cmd");

        var lines = new List<string>
        {
            "@echo off",
            "timeout /t 2 /nobreak >nul",
            $"del /f /q \"{exe}\" >nul 2>&1",
            $"if exist \"{exe}\" goto retry",
            $"rmdir /s /q \"{appDir}\" >nul 2>&1",
            $"rmdir /s /q \"{StateDir}\" >nul 2>&1",
            $"del /f /q \"{wrapperPath}\" >nul 2>&1",
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
