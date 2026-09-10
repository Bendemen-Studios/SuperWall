using System.Security.Cryptography;
using System.Text;

namespace SuperWall.Agent;

public static class LocalSecrets
{
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");

    public static string? Load(string name)
    {
        try
        {
            var path = Path.Combine(Root, name + ".bin");
            if (!File.Exists(path)) return null;
            var protectedBytes = File.ReadAllBytes(path);
            var clear = ProtectedData.Unprotect(protectedBytes, Encoding.UTF8.GetBytes("SuperWall/v1/" + name), DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(clear);
        }
        catch { return null; }
    }

    public static bool Save(string name, string value)
    {
        try
        {
            Directory.CreateDirectory(Root);
            HardenAcl(Root);
            var clear = Encoding.UTF8.GetBytes(value);
            var protectedBytes = ProtectedData.Protect(clear, Encoding.UTF8.GetBytes("SuperWall/v1/" + name), DataProtectionScope.LocalMachine);
            var path = Path.Combine(Root, name + ".bin");
            File.WriteAllBytes(path, protectedBytes);
            HardenAcl(path);
            return true;
        }
        catch { return false; }
    }

    private static void HardenAcl(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("icacls", $"\"{path}\" /inheritance:r /grant:r SYSTEM:(F) Administrators:(F)")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
