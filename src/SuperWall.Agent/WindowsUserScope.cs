using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SuperWall.Agent;

/// <summary>
/// Resolves the Windows account whose browser policy should be enforced.
/// The agent runs as LocalSystem, so HKCU is the service account rather than
/// the child. The installer records the intended interactive account before
/// elevation and this class treats that value as authoritative.
/// </summary>
public static class WindowsUserScope
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    private const string TargetUserFile = "target-user.txt";
    private const int ErrorSuccess = 0;
    private const int HKeyUsers = unchecked((int)0x80000003);
    private const int WtsUserName = 5;
    private const uint TokenUser = 1;
    private const uint TokenQuery = 0x0008;

    private static bool _loadedByUs;
    private static string? _resolvedTargetUser;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, uint tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

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
        if (!string.IsNullOrWhiteSpace(_resolvedTargetUser))
            return _resolvedTargetUser;

        try
        {
            var path = Path.Combine(StateDir, TargetUserFile);
            if (!File.Exists(path)) return null;
            var value = File.ReadAllText(path).Trim();
            if (string.IsNullOrWhiteSpace(value)) return null;
            _resolvedTargetUser = value;
            return value;
        }
        catch { return null; }
    }

    public static SecurityIdentifier? TargetSid()
    {
        return TranslateToSid(TargetUserName());
    }

    /// <summary>Returns true only when the process is running as the configured target account.</summary>
    public static bool IsTargetUserProcess(Process process)
    {
        var targetSid = TargetSid();
        if (targetSid is null) return false;

        try
        {
            if (!OpenProcessToken(process.Handle, TokenQuery, out var token)) return false;
            try
            {
                GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out var length);
                if (length <= 0) return false;
                var buffer = Marshal.AllocHGlobal(length);
                try
                {
                    if (!GetTokenInformation(token, TokenUser, buffer, length, out _)) return false;
                    var tokenUser = Marshal.ReadIntPtr(buffer);
                    var sid = new SecurityIdentifier(tokenUser);
                    return sid.Equals(targetSid);
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseHandle(token); }
        }
        catch { return false; }
    }

    public static bool SetTargetUser(string user)
    {
        if (string.IsNullOrWhiteSpace(user)) return false;

        var normalized = user.Trim();
        if (normalized.Contains('\\', StringComparison.Ordinal))
            normalized = normalized[(normalized.LastIndexOf('\\') + 1)..];

        if (string.IsNullOrWhiteSpace(normalized)) return false;
        if (TranslateToSid($"{Environment.MachineName}\\{normalized}") is null && TranslateToSid(normalized) is null)
            return false;

        try
        {
            Directory.CreateDirectory(StateDir);
            File.WriteAllText(Path.Combine(StateDir, TargetUserFile), normalized);
            _resolvedTargetUser = normalized;
            return true;
        }
        catch { return false; }
    }

    public static string? ResolveInstallTargetUser()
    {
        var active = ActiveConsoleUserName();
        return string.IsNullOrWhiteSpace(active) ? null : active;
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

    public static void UnloadTargetHiveIfLoadedByUs()
    {
        if (!_loadedByUs) return;
        var sid = TargetSid();
        if (sid is null) return;
        try { RegUnLoadKey(new IntPtr(HKeyUsers), sid.Value); }
        catch { }
        finally { _loadedByUs = false; }
    }

    private static SecurityIdentifier? TranslateToSid(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return null;
        try
        {
            if (user.Contains('\\', StringComparison.Ordinal))
                return (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier));

            var local = $"{Environment.MachineName}\\{user}";
            return (SecurityIdentifier)new NTAccount(local).Translate(typeof(SecurityIdentifier));
        }
        catch
        {
            try { return (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier)); }
            catch { return null; }
        }
    }

    private static string? ActiveConsoleUserName()
    {
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == uint.MaxValue) return null;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WtsUserName, out var buffer, out _)) return null;
            try { return Marshal.PtrToStringUni(buffer)?.Trim(); }
            finally { WTSFreeMemory(buffer); }
        }
        catch { return null; }
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
        if (result == ErrorSuccess) _loadedByUs = true;
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
