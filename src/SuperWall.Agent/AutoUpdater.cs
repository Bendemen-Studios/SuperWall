using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace SuperWall.Agent;

public sealed class AutoUpdater
{
    private const string ReleasesUrl = "https://api.github.com/repos/Bendemen-Studios/SuperWall/releases?per_page=20";
    private const string AgentAssetName = "SuperWall-Agent-win-x64.exe";
    private const string AgentChecksumName = "SHA256-Agent.txt";
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(5) };
    private readonly string _stateDir;

    public AutoUpdater(string stateDir) => _stateDir = stateDir;

    public async Task CheckAndInstallAsync(CancellationToken ct)
    {
        string? tempAgent = null;
        string? helperScript = null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ReleasesUrl);
            request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/2.2");
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
            JsonElement? selectedRelease = null;
            Version? latest = null;
            foreach (var release in doc.RootElement.EnumerateArray())
            {
                if (release.TryGetProperty("draft", out var draft) && draft.GetBoolean()) continue;
                if (release.TryGetProperty("prerelease", out var prerelease) && prerelease.GetBoolean()) continue;
                var tag = release.TryGetProperty("tag_name", out var tagElement) ? tagElement.GetString() ?? "" : "";
                if (!TryGetVersion(tag, out var candidate)) continue;
                if (latest is null || candidate > latest) { latest = candidate; selectedRelease = release; }
            }
            if (selectedRelease is null || latest is null || latest <= GetCurrentVersion()) return;

            JsonElement? agent = null;
            JsonElement? checksum = null;
            foreach (var asset in selectedRelease.Value.GetProperty("assets").EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.Equals(AgentAssetName, StringComparison.OrdinalIgnoreCase)) agent = asset;
                if (name.Equals(AgentChecksumName, StringComparison.OrdinalIgnoreCase)) checksum = asset;
            }
            if (agent is null) return;

            Directory.CreateDirectory(_stateDir);
            var target = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(target) || !File.Exists(target)) return;

            tempAgent = Path.Combine(_stateDir, $"SuperWall-Agent-{latest}.download");
            TryDelete(tempAgent);
            var downloadUrl = agent.Value.GetProperty("browser_download_url").GetString();
            if (string.IsNullOrWhiteSpace(downloadUrl)) return;
            await DownloadAsync(downloadUrl, tempAgent, ct);
            if (!IsWindowsExecutable(tempAgent)) { TryDelete(tempAgent); return; }

            if (checksum is not null)
            {
                var checksumUrl = checksum.Value.GetProperty("browser_download_url").GetString();
                if (string.IsNullOrWhiteSpace(checksumUrl)) { TryDelete(tempAgent); return; }
                var expected = (await DownloadTextAsync(checksumUrl, ct))
                    .Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault();
                await using var hashStream = File.OpenRead(tempAgent);
                var actual = Convert.ToHexString(await SHA256.HashDataAsync(hashStream, ct));
                if (string.IsNullOrWhiteSpace(expected) || !actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    TryDelete(tempAgent);
                    return;
                }
            }

            // The agent cannot replace its own executable while it is running.
            // Start an independent Windows command process that waits for the service
            // to stop, replaces the executable, then starts the service again. This
            // makes updates live without requiring a Windows reboot or user action.
            helperScript = Path.Combine(_stateDir, $"SuperWall-Agent-{latest}.update.cmd");
            var script = BuildUpdateScript(tempAgent, target, helperScript);
            await File.WriteAllTextAsync(helperScript, script, ct);

            var psi = new ProcessStartInfo
            {
                FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                Arguments = $"/d /c \"{helperScript}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var helper = Process.Start(psi);
            if (helper is null)
            {
                TryDelete(tempAgent);
                TryDelete(helperScript);
            }
            else
            {
                tempAgent = null;
                helperScript = null;
            }
        }
        catch
        {
            if (!string.IsNullOrWhiteSpace(tempAgent)) TryDelete(tempAgent);
            if (!string.IsNullOrWhiteSpace(helperScript)) TryDelete(helperScript);
        }
    }

    private static string BuildUpdateScript(string source, string target, string scriptPath)
    {
        static string Q(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";
        var sourceQ = Q(source);
        var targetQ = Q(target);
        var scriptQ = Q(scriptPath);
        return $"@echo off\r\n" +
               "setlocal\r\n" +
               "timeout /t 2 /nobreak >nul\r\n" +
               "sc.exe stop SuperWallAgent >nul 2>&1\r\n" +
               "for /l %%i in (1,1,30) do (\r\n" +
               "  sc.exe query SuperWallAgent | findstr /i \"STOPPED\" >nul && goto replace\r\n" +
               "  timeout /t 1 /nobreak >nul\r\n" +
               ")\r\n" +
               "exit /b 1\r\n" +
               ":replace\r\n" +
               $"copy /y {sourceQ} {targetQ} >nul || exit /b 1\r\n" +
               "sc.exe start SuperWallAgent >nul 2>&1\r\n" +
               $"del /f /q {sourceQ} >nul 2>&1\r\n" +
               $"del /f /q {scriptQ} >nul 2>&1\r\n" +
               "exit /b 0\r\n";
    }

    private Version GetCurrentVersion()
    {
        var value = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                     ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
        if (value.Contains('+')) value = value[..value.IndexOf('+')];
        return Version.TryParse(value, out var v) ? v : new Version(0, 0, 0);
    }

    private static bool TryGetVersion(string tag, out Version version)
    {
        version = new Version(0, 0, 0);
        if (!tag.StartsWith("kids-v", StringComparison.OrdinalIgnoreCase)) return false;
        return Version.TryParse(tag[6..], out version);
    }

    private static bool IsWindowsExecutable(string path)
    {
        try { using var stream = File.OpenRead(path); return stream.Length >= 2 && stream.ReadByte() == 'M' && stream.ReadByte() == 'Z'; }
        catch { return false; }
    }

    private async Task DownloadAsync(string url, string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/2.2");
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await input.CopyToAsync(output, ct);
    }

    private async Task<string> DownloadTextAsync(string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/2.2");
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }
}
