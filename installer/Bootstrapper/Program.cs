#nullable enable

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class Program
{
    private const string InnerResourceName = "SuperWall-Kids-Inner.exe";
    private const string TargetUserVariable = "SUPERWALL_TARGET_USER";
    private const string TargetSidVariable = "SUPERWALL_TARGET_USER_SID";
    private const string TargetUserArgument = "/SUPERWALL_TARGET_USER=";
    private const string TargetSidArgument = "/SUPERWALL_TARGET_SID=";

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, uint sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? serverName, string localGroupName, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;
    private const int ErrorSuccess = 0;
    private const int ErrorMoreData = 234;
    private const int MaxPreferredLength = -1;

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
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SuperWall",
                "InstallerCache");
            Directory.CreateDirectory(root);

            var safeTemp = Path.Combine(root, "Temp");
            Directory.CreateDirectory(safeTemp);

            runDirectory = Path.Combine(root, "run-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(runDirectory);

            var innerPath = Path.Combine(runDirectory, InnerResourceName);
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(InnerResourceName))
            {
                if (stream is null)
                    throw new InvalidOperationException("SuperWall installer payload ontbreekt.");

                using var output = new FileStream(innerPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                stream.CopyTo(output);
            }

            var target = CaptureLaunchingUser();
            if (target is null)
                throw new InvalidOperationException(
                    "SuperWall kan de oorspronkelijke Windows-gebruiker niet veilig bepalen. " +
                    "Log in op het kindaccount en start de Kids installer opnieuw.");

            var forwardedArgs = args.Select(QuoteArgument).ToList();
            forwardedArgs.Add(QuoteArgument(TargetUserArgument + target.AccountName));
            forwardedArgs.Add(QuoteArgument(TargetSidArgument + target.Sid.Value));

            var psi = new ProcessStartInfo
            {
                FileName = innerPath,
                UseShellExecute = false,
                WorkingDirectory = runDirectory,
                Arguments = string.Join(" ", forwardedArgs)
            };

            // Environment variables are retained as a convenience, but the command-line
            // parameters above are the authoritative transport across the UAC boundary.
            // Windows may recreate an elevated installer process and change its environment.
            psi.Environment["TEMP"] = safeTemp;
            psi.Environment["TMP"] = safeTemp;
            psi.Environment[TargetUserVariable] = target.AccountName;
            psi.Environment[TargetSidVariable] = target.Sid.Value;

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("SuperWall installer kon niet worden gestart.");

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
            if (!string.IsNullOrWhiteSpace(runDirectory))
                ScheduleCleanup(runDirectory);
        }
    }

    private sealed record LaunchingUser(string AccountName, SecurityIdentifier Sid);

    private static LaunchingUser? CaptureLaunchingUser()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User;

            if (sid is not null && sid.IsAccountSid() && !IsAdministrator(sid))
            {
                var accountName = identity.Name?.Trim();
                if (string.IsNullOrWhiteSpace(accountName))
                    accountName = ResolveAccountName(sid);

                if (!string.IsNullOrWhiteSpace(accountName))
                    return new LaunchingUser(accountName, sid);
            }
        }
        catch { }

        return CaptureActiveConsoleUser();
    }

    private static LaunchingUser? CaptureActiveConsoleUser()
    {
        try
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == uint.MaxValue)
                return null;

            var user = QueryWtsString(sessionId, WtsUserName);
            var domain = QueryWtsString(sessionId, WtsDomainName);
            if (string.IsNullOrWhiteSpace(user))
                return null;

            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(domain))
                candidates.Add(domain.Trim() + "\\" + user.Trim());
            candidates.Add(Environment.MachineName + "\\" + user.Trim());
            candidates.Add(user.Trim());

            foreach (var accountName in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!TryTranslateSid(accountName, out var sid) || sid is null)
                    continue;

                if (IsAdministrator(sid))
                    continue;

                var resolvedName = ResolveAccountName(sid) ?? accountName;
                return new LaunchingUser(resolvedName, sid);
            }
        }
        catch { }

        return null;
    }

    private static string? ResolveAccountName(SecurityIdentifier sid)
    {
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch { return null; }
    }

    private static bool TryTranslateSid(string accountName, out SecurityIdentifier? sid)
    {
        sid = null;
        try
        {
            sid = (SecurityIdentifier)new NTAccount(accountName).Translate(typeof(SecurityIdentifier));
            return true;
        }
        catch { return false; }
    }

    private static bool IsAdministrator(SecurityIdentifier sid)
    {
        try
        {
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var account = (NTAccount)administratorsSid.Translate(typeof(NTAccount));
            var groupName = account.Value[(account.Value.LastIndexOf('\\') + 1)..];
            IntPtr resume = IntPtr.Zero;

            do
            {
                var status = NetLocalGroupGetMembers(
                    null, groupName, 2, out var buffer, MaxPreferredLength,
                    out var entriesRead, out _, ref resume);

                if (status != ErrorSuccess && status != ErrorMoreData)
                    return true;

                try
                {
                    var size = Marshal.SizeOf<LocalGroupMembersInfo2>();
                    for (var i = 0; i < entriesRead; i++)
                    {
                        var item = Marshal.PtrToStructure<LocalGroupMembersInfo2>(buffer + i * size);
                        if (item.Sid != IntPtr.Zero && new SecurityIdentifier(item.Sid).Equals(sid))
                            return true;
                    }
                }
                finally
                {
                    if (buffer != IntPtr.Zero)
                        NetApiBufferFree(buffer);
                }

                if (status != ErrorMoreData)
                    break;
            }
            while (true);
        }
        catch
        {
            return true;
        }

        return false;
    }

    private static string? QueryWtsString(uint sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return null;

        try { return Marshal.PtrToStringUni(buffer)?.Trim(); }
        finally { WTSFreeMemory(buffer); }
    }

    private static void ScheduleCleanup(string runDirectory)
    {
        try
        {
            var escaped = runDirectory.Replace("'", "''", StringComparison.Ordinal);
            var script =
                "$path='" + escaped + "'; " +
                "Start-Sleep -Milliseconds 1000; " +
                "if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue}";

            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                ArgumentList =
                {
                    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-Command", script
                }
            });
        }
        catch { }
    }

    private static string QuoteArgument(string value)
    {
        if (value.Length == 0)
            return """";

        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"'))
            return value;

        return """ + value.Replace("\", "\\").Replace(""", "\"") + """;
    }
}