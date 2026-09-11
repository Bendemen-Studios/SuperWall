using Microsoft.Win32;
using System.Security.Principal;

namespace SuperWall.Agent;

/// <summary>
/// Resolves the Windows account that SuperWall Kids was installed for.
/// The agent itself runs as LocalSystem, so HKCU would refer to the service
/// account rather than the child. We therefore target the child's loaded HKU
/// SID hive explicitly.
/// </summary>
public static class WindowsUserScope
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    private const string TargetUserFile = "target-user.txt";

    public static string? TargetUserName()
    {
        try
        {
            var path = Path.Combine(StateDir, TargetUserFile);
            if (!File.Exists(path)) return null;
            var value = File.ReadAllText(path).Trim();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
        catch { return null; }
    }

    public static SecurityIdentifier? TargetSid()
    {
        var user = TargetUserName();
        if (string.IsNullOrWhiteSpace(user)) return null;
        try
        {
            return (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier));
        }
        catch { return null; }
    }

    public static RegistryKey? OpenUserPolicyKey(string relativePath, bool writable)
    {
        var sid = TargetSid();
        if (sid is null) return null;
        try
        {
            var fullPath = $"{sid.Value}\\{relativePath}";
            return writable
                ? Registry.Users.CreateSubKey(fullPath, true)
                : Registry.Users.OpenSubKey(fullPath, writable);
        }
        catch { return null; }
    }

    public static string? ProfilePath()
    {
        var sid = TargetSid();
        if (sid is null) return null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid.Value}");
            var path = key?.GetValue("ProfileImagePath") as string;
            return string.IsNullOrWhiteSpace(path) ? null : Environment.ExpandEnvironmentVariables(path);
        }
        catch { return null; }
    }
}
