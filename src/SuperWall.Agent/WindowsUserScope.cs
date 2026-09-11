using Microsoft.Win32;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SuperWall.Agent;

/// <summary>
/// Resolves the Windows account that SuperWall Kids was installed for.
/// The agent itself runs as LocalSystem, so HKCU would refer to the service
/// account rather than the child. We therefore target the child's HKU SID hive
/// explicitly and load the profile hive when the child is currently logged out.
/// </summary>
public static class WindowsUserScope
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    private const string TargetUserFile = "target-user.txt";
    private const int ErrorSuccess = 0;
    private const int HKeyUsers = unchecked((int)0x80000003);
    private static bool _loadedByUs;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

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
            EnsureTargetHiveLoaded(sid);
            var fullPath = $"{sid.Value}\\{relativePath}";
            return writable
                ? Registry.Users.CreateSubKey(fullPath, true)
                : Registry.Users.OpenSubKey(fullPath, writable);
        }
        catch { return null; }
    }

    /// <summary>
    /// Unloads a target profile hive only when this service loaded it itself.
    /// This lets policy changes persist for a user who is currently logged out
    /// without leaving an extra HKU hive mounted permanently.
    /// </summary>
    public static void UnloadTargetHiveIfLoadedByUs()
    {
        if (!_loadedByUs) return;
        var sid = TargetSid();
        if (sid is null) return;
        try
        {
            RegUnLoadKey(new IntPtr(HKeyUsers), sid.Value);
        }
        catch { }
        finally
        {
            _loadedByUs = false;
        }
    }

    private static void EnsureTargetHiveLoaded(SecurityIdentifier sid)
    {
        var sidText = sid.Value;
        using (var existing = Registry.Users.OpenSubKey(sidText))
        {
            if (existing is not null) return;
        }

        var profile = ProfilePath(sid);
        if (string.IsNullOrWhiteSpace(profile)) return;
        var hiveFile = Path.Combine(profile, "NTUSER.DAT");
        if (!File.Exists(hiveFile)) return;

        var result = RegLoadKey(new IntPtr(HKeyUsers), sidText, hiveFile);
        if (result == ErrorSuccess)
            _loadedByUs = true;
    }

    public static string? ProfilePath()
    {
        var sid = TargetSid();
        return sid is null ? null : ProfilePath(sid);
    }

    private static string? ProfilePath(SecurityIdentifier sid)
    {
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
