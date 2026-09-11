using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SuperWall.Agent;

/// <summary>
/// Resolves the Windows account whose browser policy should be enforced.
/// The agent runs as LocalSystem, so HKCU is the service account rather than
/// the child. We therefore target the enrolled user's HKU SID hive and, when
/// possible, prefer the currently active interactive Windows session.
/// </summary>
public static class WindowsUserScope
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    private const string TargetUserFile = "target-user.txt";
    private const int ErrorSuccess = 0;
    private const int HKeyUsers = unchecked((int)0x80000003);
    private const int WtsCurrentServerHandle = 0;
    private const int WtsUserName = 5;
    private static bool _loadedByUs;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        uint sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

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
        // The active console account is the account actually using the local
        // desktop. Prefer it so an administrator installing SuperWall for a
        // child account cannot accidentally leave policies on the administrator.
        var active = ActiveConsoleUserName();
        var activeSid = TranslateToSid(active);
        if (activeSid is not null)
        {
            PersistTargetUser(active!);
            return activeSid;
        }

        return TranslateToSid(TargetUserName());
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

    private static SecurityIdentifier? TranslateToSid(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return null;
        try
        {
            return (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier));
        }
        catch { return null; }
    }

    private static string? ActiveConsoleUserName()
    {
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == uint.MaxValue) return null;

            if (!WTSQuerySessionInformation(
                    IntPtr.Zero,
                    sessionId,
                    WtsUserName,
                    out var buffer,
                    out _))
                return null;

            try
            {
                var user = Marshal.PtrToStringUni(buffer)?.Trim();
                if (string.IsNullOrWhiteSpace(user)) return null;

                // WTSUserName returns only the account name. Prefix it with the
                // local machine name so NTAccount translation is deterministic.
                return $"{Environment.MachineName}\\{user}";
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }
        catch { return null; }
    }

    private static void PersistTargetUser(string user)
    {
        try
        {
            Directory.CreateDirectory(StateDir);
            var path = Path.Combine(StateDir, TargetUserFile);
            if (!string.Equals(TargetUserName(), user, StringComparison.OrdinalIgnoreCase))
                File.WriteAllText(path, user);
        }
        catch { }
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
