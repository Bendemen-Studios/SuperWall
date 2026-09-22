using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SuperWall.Agent;

public static class WindowsUserScope
{
    private static readonly string StateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");
    private const string TargetUserFile = "target-user.txt";
    private const int ErrorSuccess = 0;
    private const int HKeyUsers = unchecked((int)0x80000003);
    private const int WtsUserName = 5;
    private const uint TokenUser = 1;
    private const uint TokenQuery = 0x0008;
    private const int MaxPreferredLength = -1;
    private const int NetApiStatusMoreData = 234;
    private static bool _loadedByUs;
    private static string? _resolvedTargetUser;

    // LOCALGROUP_MEMBERS_INFO_2: PSID, SID_NAME_USE, LPWSTR.
    // Keeping this ABI layout correct is critical: the old layout read a domain-name
    // pointer as a SID and made valid child accounts fail the UAC enrollment check.
    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo2 { public IntPtr Sid; public int Usage; public IntPtr DomainAndName; }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr tokenHandle, uint tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool WTSQuerySessionInformation(IntPtr hServer, uint sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);
    [DllImport("Wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr pMemory);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);
    [DllImport("Netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);

    public static string? TargetUserName()
    {
        if (!string.IsNullOrWhiteSpace(_resolvedTargetUser)) return _resolvedTargetUser;
        try
        {
            var path = Path.Combine(StateDir, TargetUserFile);
            var configured = File.Exists(path) ? File.ReadAllText(path).Trim() : null;
            if (!string.IsNullOrWhiteSpace(configured) && TryResolveNonAdmin(configured, out var resolved)) { _resolvedTargetUser = resolved; return resolved; }
            var active = ActiveConsoleUserName();
            if (!string.IsNullOrWhiteSpace(active) && TryResolveNonAdmin(active, out resolved)) { _resolvedTargetUser = resolved; TryPersistTargetUser(resolved); return resolved; }
            return null;
        }
        catch { return null; }
    }

    public static SecurityIdentifier? TargetSid() => TranslateToSid(TargetUserName());

    public static bool IsTargetUserProcess(Process process)
    {
        var targetSid = TargetSid(); if (targetSid is null) return false;
        try
        {
            if (!OpenProcessToken(process.Handle, TokenQuery, out var token)) return false;
            try
            {
                GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out var length); if (length <= 0) return false;
                var buffer = Marshal.AllocHGlobal(length);
                try { if (!GetTokenInformation(token, TokenUser, buffer, length, out _)) return false; return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Equals(targetSid); }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseHandle(token); }
        }
        catch { return false; }
    }

    public static bool SetTargetUser(string user)
    {
        if (string.IsNullOrWhiteSpace(user)) return false;
        if (!TryResolveNonAdmin(user.Trim(), out var resolved)) return false;
        return TryPersistTargetUser(resolved);
    }

    public static string? ResolveInstallTargetUser()
    {
        var active = ActiveConsoleUserName();
        return !string.IsNullOrWhiteSpace(active) && TryResolveNonAdmin(active, out var resolved) ? resolved : null;
    }

    public static RegistryKey? OpenUserPolicyKey(string relativePath, bool writable)
    {
        var sid = TargetSid(); if (sid is null) return null;
        try { EnsureTargetHiveLoaded(sid); var fullPath = $"{sid.Value}\\{relativePath}"; return writable ? Registry.Users.CreateSubKey(fullPath, true) : Registry.Users.OpenSubKey(fullPath, writable); }
        catch { return null; }
    }

    public static void UnloadTargetHiveIfLoadedByUs()
    {
        if (!_loadedByUs) return; var sid = TargetSid(); if (sid is null) return;
        try { RegUnLoadKey(new IntPtr(HKeyUsers), sid.Value); } catch { } finally { _loadedByUs = false; }
    }

    private static bool TryResolveNonAdmin(string user, out string resolved)
    {
        resolved = user.Trim(); var sid = TranslateToSid(resolved); if (sid is null) return false;
        return !IsLocalAdministrator(sid);
    }

    private static SecurityIdentifier? TranslateToSid(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return null;
        try
        {
            if (user.Contains('\\', StringComparison.Ordinal)) return (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier));
            return (SecurityIdentifier)new NTAccount($"{Environment.MachineName}\\{user}").Translate(typeof(SecurityIdentifier));
        }
        catch { try { return (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier)); } catch { return null; } }
    }

    private static bool IsLocalAdministrator(SecurityIdentifier sid)
    {
        try
        {
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var account = (NTAccount)administratorsSid.Translate(typeof(NTAccount));
            var groupName = account.Value[(account.Value.LastIndexOf('\\') + 1)..]; IntPtr resume = IntPtr.Zero;
            do
            {
                var status = NetLocalGroupGetMembers(null, groupName, 2, out var buffer, MaxPreferredLength, out var entriesRead, out _, ref resume);
                // Fail closed. If Windows cannot enumerate the Administrators group,
                // never silently treat the target as safe.
                if (status != ErrorSuccess && status != NetApiStatusMoreData) return true;
                try
                {
                    var size = Marshal.SizeOf<LocalGroupMembersInfo2>();
                    for (var i = 0; i < entriesRead; i++) { var item = Marshal.PtrToStructure<LocalGroupMembersInfo2>(buffer + i * size); if (item.Sid != IntPtr.Zero && new SecurityIdentifier(item.Sid).Equals(sid)) return true; }
                }
                finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
                if (status != NetApiStatusMoreData) break;
            } while (true);
        }
        catch { return true; }
        return false;
    }

    private static bool TryPersistTargetUser(string user)
    {
        try { Directory.CreateDirectory(StateDir); File.WriteAllText(Path.Combine(StateDir, TargetUserFile), user.Trim()); _resolvedTargetUser = user.Trim(); return true; }
        catch { return false; }
    }

    private static string? ActiveConsoleUserName()
    {
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId(); if (sessionId == uint.MaxValue) return null;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WtsUserName, out var buffer, out _)) return null;
            try { return Marshal.PtrToStringUni(buffer)?.Trim(); } finally { WTSFreeMemory(buffer); }
        }
        catch { return null; }
    }

    private static void EnsureTargetHiveLoaded(SecurityIdentifier sid)
    {
        var sidText = sid.Value; using (var existing = Registry.Users.OpenSubKey(sidText)) { if (existing is not null) return; }
        var profile = ProfilePath(sid); if (string.IsNullOrWhiteSpace(profile)) return;
        var hiveFile = Path.Combine(profile, "NTUSER.DAT"); if (!File.Exists(hiveFile)) return;
        if (RegLoadKey(new IntPtr(HKeyUsers), sidText, hiveFile) == ErrorSuccess) _loadedByUs = true;
    }

    public static string? ProfilePath() { var sid = TargetSid(); return sid is null ? null : ProfilePath(sid); }

    private static string? ProfilePath(SecurityIdentifier sid)
    {
        try { using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid.Value}"); var path = key?.GetValue("ProfileImagePath") as string; return string.IsNullOrWhiteSpace(path) ? null : Environment.ExpandEnvironmentVariables(path); }
        catch { return null; }
    }
}
