using System.Security.Cryptography;
using System.Text;

namespace SuperWall.Agent;

public static class LocalSecrets
{
    private static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");
    public static string? Load(string name)
    {
        try
        {
            var path = Path.Combine(Root, name + ".bin");
            if (!File.Exists(path)) return null;
            var clear = ProtectedData.Unprotect(File.ReadAllBytes(path), Encoding.UTF8.GetBytes("SuperWall/v1/" + name), DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(clear);
        }
        catch { return null; }
    }
    public static bool Save(string name, string value)
    {
        try
        {
            Directory.CreateDirectory(Root);
            var bytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Encoding.UTF8.GetBytes("SuperWall/v1/" + name), DataProtectionScope.LocalMachine);
            var path = Path.Combine(Root, name + ".bin");
            File.WriteAllBytes(path, bytes);
            if (OperatingSystem.IsWindows())
            {
                using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("icacls", $"\"{path}\" /inheritance:r /grant:r SYSTEM:(F) Administrators:(F)") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
                p?.WaitForExit(5000);
            }
            return true;
        }
        catch { return false; }
    }
}
