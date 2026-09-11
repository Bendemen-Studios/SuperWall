using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace SuperWall.Agent;

public sealed class AutoUpdater
{
    private const string LatestReleaseUrl = "https://api.github.com/repos/Bendemen-Studios/SuperWall/releases/latest";
    private const string InstallerPrefix = "SuperWall-Kids-Setup-";
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(5) };
    private readonly string _stateDir;

    public AutoUpdater(string stateDir) => _stateDir = stateDir;

    public async Task CheckAndInstallAsync(CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, LatestReleaseUrl);
            request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/1.0");
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
            var root = doc.RootElement;
            var tag = root.GetProperty("tag_name").GetString() ?? "";
            if (!TryGetVersion(tag, out var latest)) return;

            var current = GetCurrentVersion();
            if (latest <= current) return;

            var assets = root.GetProperty("assets");
            JsonElement? installer = null;
            JsonElement? checksum = null;
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.StartsWith(InstallerPrefix, StringComparison.OrdinalIgnoreCase) && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) installer = asset;
                if (name.Equals("SHA256.txt", StringComparison.OrdinalIgnoreCase)) checksum = asset;
            }
            if (installer is null) return;

            Directory.CreateDirectory(_stateDir);
            var tempInstaller = Path.Combine(_stateDir, $"SuperWall-Kids-Setup-{latest}.exe");
            await DownloadAsync(installer.Value.GetProperty("browser_download_url").GetString()!, tempInstaller, ct);

            if (checksum is not null)
            {
                var expected = await DownloadTextAsync(checksum.Value.GetProperty("browser_download_url").GetString()!, ct);
                var expectedHash = expected.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(File.OpenRead(tempInstaller), ct));
                if (string.IsNullOrWhiteSpace(expectedHash) || !actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    TryDelete(tempInstaller);
                    return;
                }
            }

            var psi = new ProcessStartInfo
            {
                FileName = tempInstaller,
                // Let the bootstrapper start the real Inno installer without pre-elevating it.
                // This allows the bootstrapper to provide a writable TEMP/TMP location first.
                Arguments = "/UPGRADE=1 /VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(tempInstaller) ?? _stateDir
            };
            Process.Start(psi);
        }
        catch { }
    }

    private Version GetCurrentVersion()
    {
        var value = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                     ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
                     ?? "0.0.0";
        if (value.Contains('+')) value = value[..value.IndexOf('+')];
        return Version.TryParse(value, out var v) ? v : new Version(0, 0, 0);
    }

    private static bool TryGetVersion(string tag, out Version version)
    {
        version = new Version(0, 0, 0);
        var value = tag.StartsWith("kids-v", StringComparison.OrdinalIgnoreCase) ? tag[6..] : tag.TrimStart('v', 'V');
        return Version.TryParse(value, out version);
    }

    private async Task DownloadAsync(string url, string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/1.0");
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        await using var output = File.Create(path);
        await input.CopyToAsync(output, ct);
    }

    private async Task<string> DownloadTextAsync(string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/1.0");
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }
}
