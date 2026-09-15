#nullable enable

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class Program
{
    private const string InnerResourceName = "SuperWall-Kids-Inner.exe";

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        uint sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    private const int WtsUserName = 5;

    [STAThread]
    private static int Main(string[] args)
    {
        string? runDirectory = null;
        try
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SuperWall", "InstallerCache");
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

            // This bootstrapper is explicitly non-elevated. WindowsIdentity normally
            // identifies the user who launched the installer, before the inner Inno
            // Setup process requests UAC elevation. Never pass an administrator as
            // the parental-control target; when launched from an admin context, use
            // the active console account only when that account is non-admin.
            var targetUser = GetOriginalWindowsUser();
            if (string.IsNullOrWhiteSpace(targetUser))
                throw new InvalidOperationException("SuperWall kon geen veilige niet-beheerders Windows-gebruiker bepalen. Start de Kids installer vanuit het kindaccount.");

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
        // The bootstrapper runs asInvoker, so a normal child account remains
        // identifiable before UAC. If it is already running in an administrator
        // context, do not use that identity as the target.
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var name = identity.Name?.Trim();
            if (!string.IsNullOrWhiteSpace(name) && !IsAdministrator(identity))
                return name;
        }
        catch { }

        // Fallback for unusual launch contexts, and for an installer started from
        // an administrator context while a non-admin child account is interactive.
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
                return IsSafeTargetUser(user) ? user : null;
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }
        catch { return null; }
    }

    private static bool IsAdministrator(WindowsIdentity identity)
    {
        try
        {
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return true; }
    }

    private static bool IsSafeTargetUser(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return false;
        try
        {
            var account = user.Contains('\\', StringComparison.Ordinal)
                ? user
                : $"{Environment.MachineName}\\{user}";
            var sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            return !IsMemberOfAdministrators(sid, administratorsSid);
        }
        catch { return false; }
    }

    private static bool IsMemberOfAdministrators(SecurityIdentifier userSid, SecurityIdentifier administratorsSid)
    {
        try
        {
            using var identity = new WindowsIdentity(userSid.Value);
            return new WindowsPrincipal(identity).IsInRole(administratorsSid);
        }
        catch
        {
            // A failed administrator check must never turn into an unsafe target.
            return true;
        }
    }

    private static string QuoteArgument(string value)
    {
        if (value.Length == 0) return "\"\"";
        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"')) return value;
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
}
