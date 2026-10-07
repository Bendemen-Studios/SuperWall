using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SuperWall.Agent;

internal static class InteractiveProcessLauncher
{
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint TokenAccess = TokenAssignPrimary | TokenDuplicate | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const int TokenPrimary = 1;
    private const int SecurityImpersonation = 2;
    private const int TokenSessionId = 12;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr primaryToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        ref uint tokenInformation,
        int tokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr token,
        string? applicationName,
        string? commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static void Start(string executablePath, string arguments)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();

        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == uint.MaxValue)
            throw new InvalidOperationException("Geen actieve Windows-gebruikerssessie gevonden.");

        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TokenAccess, out var sourceToken))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Kon het SYSTEM-token niet openen.");

        try
        {
            if (!DuplicateTokenEx(sourceToken, TokenAccess, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out var userToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Kon het interactieve token niet maken.");

            try
            {
                if (!SetTokenInformation(userToken, TokenSessionId, ref sessionId, sizeof(uint)))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Kon de update-installer aan de actieve gebruikerssessie koppelen.");

                var startup = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    lpDesktop = @"winsta0\default"
                };

                var commandLine = Quote(executablePath) + (string.IsNullOrWhiteSpace(arguments) ? "" : " " + arguments);
                if (!CreateProcessAsUser(
                        userToken,
                        executablePath,
                        commandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        CreateUnicodeEnvironment,
                        IntPtr.Zero,
                        Path.GetDirectoryName(executablePath),
                        ref startup,
                        out var processInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Kon de update-installer niet starten.");
                }

                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
            }
            finally
            {
                CloseHandle(userToken);
            }
        }
        finally
        {
            CloseHandle(sourceToken);
        }
    }

    private static string Quote(string value) =>
        """ + value.Replace(""", "\"", StringComparison.Ordinal) + """;
}
