using System.Threading;
using Microsoft.Data.Sqlite;

namespace SuperWall.Dashboard;

internal static class EnrollmentKeyCleanup
{
    private static Timer? _timer;

    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void Initialize()
    {
        _timer = new Timer(Cleanup, null, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1));
    }

    private static void Cleanup(object? _)
    {
        try
        {
            var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
            var db = Path.Combine(dataDir, "superwall.db");
            if (!File.Exists(db)) return;

            using var connection = new SqliteConnection($"Data Source={db}");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM enrollment_keys WHERE expires_utc <= $now";
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            command.ExecuteNonQuery();
        }
        catch
        {
            // Cleanup must never affect the dashboard process.
        }
    }
}
