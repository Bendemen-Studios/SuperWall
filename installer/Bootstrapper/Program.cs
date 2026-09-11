using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

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

            // Never overwrite a shared inner-installer executable. A running previous
            // installer can still hold a handle on it during an upgrade.
            runDirectory = Path.Combine(root, "run-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(runDirectory);
            var innerPath = Path.Combine(runDirectory, InnerResourceName);

            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(InnerResourceName))
            {
                if (stream is null)
                    throw new InvalidOperationException("SuperWall installer payload ontbreekt.");

                using var output = File.CreateNew(innerPath);
                stream.CopyTo(output);
            }

            var targetUser = GetInteractiveUser();

            var psi = new ProcessStartInfo
            {
                FileName = innerPath,
                UseShellExecute = false,
                WorkingDirectory = runDirectory,
                Arguments = string.Join(" ", args.Select(QuoteArgument))
            };

            psi.Environment["TEMP"] = safeTemp;
            psi.Environment["TMP"] = safeTemp;
            if (!string.IsNullOrWhiteSpace(targetUser))
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

    private static string? GetInteractiveUser()
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
                return string.IsNullOrWhiteSpace(user) ? null : user;
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }
        catch { return null; }
    }

    private static string QuoteArgument(string value)
    {
        if (value.Length == 0) return "\"\"";
        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"')) return value;
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
}
