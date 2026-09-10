using System.Diagnostics;

namespace SuperWall.Agent;

public static class SecurityHardening
{
    private const string StateDir = @"C:\ProgramData\SuperWall";
    private const string ServiceName = "SuperWallAgent";

    // SYSTEM and local Administrators retain full control. Authenticated users can
    // only query the service; they cannot start, stop, pause or reconfigure it.
    private const string ServiceSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCRP;;;AU)";

    public static void Apply()
    {
        if (!OperatingSystem.IsWindows()) return;
        HardenStateDirectory();
        HardenQuarantineDirectory();
        ConfigureServiceRecovery();
        ConfigureServiceAcl();
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

    private static void HardenQuarantineDirectory()
    {
        try
        {
            var quarantine = Path.Combine(StateDir, "Quarantine");
            Directory.CreateDirectory(quarantine);
            Run("icacls", $"\"{quarantine}\" /inheritance:r");
            Run("icacls", $"\"{quarantine}\" /grant:r \"SYSTEM:(OI)(CI)(F)\"");
            Run("icacls", $"\"{quarantine}\" /grant:r \"Administrators:(OI)(CI)(F)\"");
            Run("icacls", $"\"{quarantine}\" /grant:r \"Users:(OI)(CI)(RX)\"");
            Run("icacls", $"\"{quarantine}\" /deny \"Users:(W,DC,WDAC,WEA)\"");
        }
        catch { }
    }

    private static void ConfigureServiceRecovery()
    {
        Run("sc.exe", $"failure {ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000");
        Run("sc.exe", $"failureflag {ServiceName} 1");
    }

    private static void ConfigureServiceAcl()
    {
        Run("sc.exe", $"sdset {ServiceName} {ServiceSddl}");
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
                WindowStyle = ProcessWindowStyle.Hidden
            });
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
