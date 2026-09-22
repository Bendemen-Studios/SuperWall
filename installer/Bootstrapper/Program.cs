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

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, uint sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;

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

            // The bootstrapper is deliberately asInvoker. Capture the exact identity that
            // launched this process before the UAC boundary is crossed by the inner installer.
            var target = CaptureLaunchingUser();
            if (target is null)
                throw new InvalidOperationException(
                    "SuperWall kan de oorspronkelijke Windows-gebruiker niet veilig bepalen. " +
                    "Start de Kids installer rechtstreeks vanuit het kindaccount.");

            var psi = new ProcessStartInfo
            {
                FileName = innerPath,
                UseShellExecute = false,
                WorkingDirectory = runDirectory,
                Arguments = string.Join(" ", args.Select(QuoteArgument))
            };

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

            // Never allow an already-elevated/admin identity to become the child target.
            if (!identity.User?.IsAccountSid() ?? true)
                return null;

            var sid = identity.User;
            if (sid is null)
                return null;

            var accountName = identity.Name?.Trim();
            if (string.IsNullOrWhiteSpace(accountName))
                accountName = ResolveAccountName(sid);

            if (string.IsNullOrWhiteSpace(accountName))
                return null;

            if (IsAdministrator(sid))
                return null;

            return new LaunchingUser(accountName, sid);
        }
        catch
        {
            // Fallback for a normal non-elevated launcher where WindowsIdentity.Name may
            // be unavailable in unusual provider configurations: resolve the active console
            // session, but only as a fallback and only after checking it is non-admin.
            return CaptureActiveConsoleUser();
        }
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

            var accountName = string.IsNullOrWhiteSpace(domain)
                ? user.Trim()
                : domain.Trim() + "\\" + user.Trim();

            if (!TryTranslateSid(accountName, out var sid) || sid is null)
                return null;

            if (IsAdministrator(sid))
                return null;

            return new LaunchingUser(accountName, sid);
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveAccountName(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            return null;
        }
    }

    private static bool TryTranslateSid(string accountName, out SecurityIdentifier? sid)
    {
        sid = null;
        try
        {
            sid = (SecurityIdentifier)new NTAccount(accountName).Translate(typeof(SecurityIdentifier));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsAdministrator(SecurityIdentifier sid)
    {
        try
        {
            var identity = new WindowsIdentity(sid.Value);
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            try
            {
                var current = WindowsIdentity.GetCurrent();
                return current.User?.Equals(sid) == true &&
                       new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return true;
            }
        }
    }

    private static string? QueryWtsString(uint sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return null;

        try
        {
            return Marshal.PtrToStringUni(buffer)?.Trim();
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
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
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script
                }
            });
        }
        catch { }
    }

    private static string QuoteArgument(string value)
    {
        if (value.Length == 0)
            return "\"\"";

        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"'))
            return value;

        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
}