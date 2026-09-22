#nullable enable

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class Program
{
    private const string InnerResourceName = "SuperWall-Kids-Inner.exe";
    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;
    private const int ErrorSuccess = 0;
    private const int NetApiStatusMoreData = 234;
    private const int MaxPreferredLength = -1;

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, uint sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);
    [DllImport("Wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr pMemory);
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);
    [DllImport("Netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);

    // Correct LOCALGROUP_MEMBERS_INFO_2 layout: PSID, SID_NAME_USE, LPWSTR.
    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo2
    {
        public IntPtr Sid;
        public int Usage;
        public IntPtr DomainAndName;
    }

    [STAThread]
    private static int Main(string[] args)
    {
        string? runDirectory = null;
        try
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SuperWall", "InstallerCache");
            Directory.CreateDirectory(root);
            var safeTemp = Path.Combine(root, "Temp");
            Directory.CreateDirectory(safeTemp);
            runDirectory = Path.Combine(root, "run-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(runDirectory);

            var innerPath = Path.Combine(runDirectory, InnerResourceName);
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(InnerResourceName))
            {
                if (stream is null) throw new InvalidOperationException("SuperWall installer payload ontbreekt.");
                using var output = new FileStream(innerPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                stream.CopyTo(output);
            }

            // Capture the interactive user, not merely the elevated/admin process identity.
            // UAC can change the token seen by the bootstrapper while the child account remains
            // the active console user. The inner installer receives the original account name.
            var targetUser = GetOriginalWindowsUser();
            if (string.IsNullOrWhiteSpace(targetUser))
                throw new InvalidOperationException("SuperWall kon de oorspronkelijke Windows-gebruiker van de actieve sessie niet veilig bepalen. Meld het kindaccount aan en probeer de installatie opnieuw.");

            var psi = new ProcessStartInfo
            {
                FileName = innerPath,
                UseShellExecute = false,
                WorkingDirectory = runDirectory,
                Arguments = string.Join(" ", args.Select(QuoteArgument))
            };
            psi.Environment["TEMP"] = safeTemp;
            psi.Environment["TMP"] = safeTemp;
            psi.Environment["SUPERWALL_TARGET_USER"] = targetUser;

            using var process = Process.Start(psi) ?? throw new InvalidOperationException("SuperWall installer kon niet worden gestart.");
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            try
            {
                System.Windows.Forms.MessageBox.Show(
                    "SuperWall Kids kan de installer niet starten.\n\n" + ex.Message,
                    "SuperWall Kids",
                    System.Windows.Forms.MessageBoxButtons.OK,
                    System.Windows.Forms.MessageBoxIcon.Error);
            }
            catch { }
            return 1;
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(runDirectory)) ScheduleCleanup(runDirectory);
        }
    }

    private static void ScheduleCleanup(string runDirectory)
    {
        try
        {
            var escaped = runDirectory.Replace("'", "''", StringComparison.Ordinal);
            var script = "$path='" + escaped + "'; Start-Sleep -Milliseconds 1000; if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue}";
            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                ArgumentList = { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script }
            });
        }
        catch { }
    }

    private static string? GetOriginalWindowsUser()
    {
        // First prefer the current identity when the bootstrapper was launched normally.
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var name = identity.Name?.Trim();
            if (!string.IsNullOrWhiteSpace(name) && !IsAdministrator(identity))
                return name;
        }
        catch { }

        // When UAC has elevated the bootstrapper, WindowsIdentity.GetCurrent() can represent
        // the administrator instead of the child. Resolve the active console session instead.
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == uint.MaxValue) return null;

            var user = QueryWtsString(sessionId, WtsUserName);
            var domain = QueryWtsString(sessionId, WtsDomainName);
            if (string.IsNullOrWhiteSpace(user)) return null;

            // Preserve the domain when Windows supplies one. This is important for Microsoft,
            // Azure AD, and other account providers where MACHINE\\user is not resolvable.
            var target = string.IsNullOrWhiteSpace(domain)
                ? user.Trim()
                : domain.Trim() + "\\" + user.Trim();

            return IsSafeTargetUser(target) ? target : null;
        }
        catch { return null; }
    }

    private static string? QueryWtsString(uint sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return null;
        try { return Marshal.PtrToStringUni(buffer)?.Trim(); }
        finally { WTSFreeMemory(buffer); }
    }

    private static bool IsAdministrator(WindowsIdentity identity)
    {
        try { return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return true; }
    }

    private static bool IsSafeTargetUser(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return false;
        try
        {
            // Resolve the exact provider-qualified account first. Only fall back to the local
            // machine for an unqualified local username; do not turn Microsoft/AAD identities
            // into MACHINE\\username because that can make a valid child account look missing.
            var accountName = user.Contains('\\', StringComparison.Ordinal)
                ? user
                : $"{Environment.MachineName}\\{user}";
            var sid = (SecurityIdentifier)new NTAccount(accountName).Translate(typeof(SecurityIdentifier));
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            return !IsMemberOfLocalAdministrators(sid, administratorsSid);
        }
        catch
        {
            // Some Microsoft/Azure AD identities cannot be translated through NTAccount on every
            // Windows configuration. The session supplied by WTS is still authoritative; allow
            // the identity when it is provider-qualified instead of rejecting the child outright.
            return user.Contains('\\', StringComparison.Ordinal) &&
                   !string.Equals(user, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                   !user.EndsWith("\\Administrator", StringComparison.OrdinalIgnoreCase);
        }
    }

    private static bool IsMemberOfLocalAdministrators(SecurityIdentifier userSid, SecurityIdentifier administratorsSid)
    {
        try
        {
            var account = (NTAccount)administratorsSid.Translate(typeof(NTAccount));
            var groupName = account.Value[(account.Value.LastIndexOf('\\') + 1)..];
            IntPtr resume = IntPtr.Zero;
            do
            {
                var status = NetLocalGroupGetMembers(null, groupName, 2, out var buffer, MaxPreferredLength, out var entriesRead, out _, ref resume);
                if (status != ErrorSuccess && status != NetApiStatusMoreData) return true;
                try
                {
                    var size = Marshal.SizeOf<LocalGroupMembersInfo2>();
                    for (var i = 0; i < entriesRead; i++)
                    {
                        var item = Marshal.PtrToStructure<LocalGroupMembersInfo2>(buffer + i * size);
                        if (item.Sid != IntPtr.Zero && new SecurityIdentifier(item.Sid).Equals(userSid)) return true;
                    }
                }
                finally
                {
                    if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
                }
                if (status != NetApiStatusMoreData) break;
            }
            while (true);
        }
        catch { return true; }
        return false;
    }

    private static string QuoteArgument(string value)
    {
        if (value.Length == 0) return "\"\"";
        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"')) return value;
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
}
