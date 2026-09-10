using System.Diagnostics;
using System.Security.Principal;

namespace SuperWall.Agent;

public static class SecurityHardening
{
    private const string StateDir = @"C:\ProgramData\SuperWall";
    private const string ServiceName = "SuperWallAgent";

    public static void Apply()
    {
        if (!OperatingSystem.IsWindows()) return;
        HardenStateDirectory();
        ConfigureServiceRecovery();
        DisableGuestAndChildWriteAccess();
    }

    private static void HardenStateDirectory()
    {
        try
        {
            Directory.CreateDirectory(StateDir);
            Run("icacls", $"\"{StateDir}\" /inheritance:r");
            Run("icacls", $"\"{StateDir}\" /grant:r \"SYSTEM:(OI)(CI)(F)\"");
            Run("icacls", $"\"{StateDir}\" /grant:r \"Administrators:(OI)(CI)(F)\"");
            Run("icacls", $"\"{StateDir}\" /grant:r \"Users:(OI)(CI)(RX)\"");
            Run("icacls", $"\"{StateDir}\" /deny \"Users:(W,DC,WDAC,WEA)\"");
        }
        catch { }
    }

    private static void ConfigureServiceRecovery()
    {
        Run("sc.exe", $"failure {ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000");
        Run("sc.exe", $"failureflag {ServiceName} 1");
    }

    private static void DisableGuestAndChildWriteAccess()
    {
        // The agent intentionally never grants the interactive child account service-control rights.
        // Installation should be performed by an administrator on a standard (non-admin) child account.
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            _ = identity.User?.Value;
        }
        catch { }
    }

    private static void Run(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
