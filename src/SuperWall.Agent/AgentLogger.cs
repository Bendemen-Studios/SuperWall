namespace SuperWall.Agent;

internal static class AgentLogger
{
    private static readonly object Gate = new();
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");
    private static readonly string LogPath = Path.Combine(StateDir, "agent.log");

    public static void Info(string message) => Write("INFO", message);
    public static void Error(string message, Exception? ex = null)
        => Write("ERROR", ex is null ? message : $"{message} ({ex.GetType().Name}: {ex.Message})");

    private static void Write(string level, string message)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(StateDir);
                if (File.Exists(LogPath) && new FileInfo(LogPath).Length > 1024 * 1024)
                {
                    var backup = LogPath + ".1";
                    try { File.Delete(backup); } catch { }
                    try { File.Move(LogPath, backup); } catch { }
                }

                File.AppendAllText(LogPath,
                    $"{DateTimeOffset.UtcNow:O} [{level}] {message}{Environment.NewLine}");
            }
        }
        catch { }
    }
}
