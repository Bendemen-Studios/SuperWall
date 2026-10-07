using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace SuperWall.Agent;

public sealed class AutoUpdater
{
    private const string ReleasesUrl = "https://api.github.com/repos/Bendemen-Studios/SuperWall/releases?per_page=20";
    private const string ChecksumName = "SHA256.txt";
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(10) };
    private readonly string _stateDir;

    public AutoUpdater(string stateDir) => _stateDir = stateDir;

    public async Task CheckAndInstallAsync(CancellationToken ct)
    {
        string? installer = null;
        string? checksum = null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ReleasesUrl);
            request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/3.0");
            request.Headers.Accept.ParseAdd("application/vnd.github+json");

            using var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                AgentLogger.Error($"Update check failed with HTTP {(int)response.StatusCode} ({response.ReasonPhrase}).");
                return;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
            JsonElement? selectedRelease = null;
            Version? latest = null;

            foreach (var release in doc.RootElement.EnumerateArray())
            {
                if (release.TryGetProperty("draft", out var draft) && draft.GetBoolean()) continue;
                if (release.TryGetProperty("prerelease", out var prerelease) && prerelease.GetBoolean()) continue;

                var tag = release.TryGetProperty("tag_name", out var tagElement) ? tagElement.GetString() ?? "" : "";
                if (!TryGetVersion(tag, out var candidate)) continue;

                if (latest is null || candidate > latest)
                {
                    latest = candidate;
                    selectedRelease = release;
                }
            }

            var current = GetCurrentVersion();
            if (selectedRelease is null || latest is null || latest <= current)
                return;

            JsonElement? installerAsset = null;
            JsonElement? checksumAsset = null;
            foreach (var asset in selectedRelease.Value.GetProperty("assets").EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.Equals($"SuperWall-Kids-Setup-{latest}.exe", StringComparison.OrdinalIgnoreCase))
                    installerAsset = asset;
                else if (name.Equals(ChecksumName, StringComparison.OrdinalIgnoreCase))
                    checksumAsset = asset;
            }

            if (installerAsset is null || checksumAsset is null)
            {
                AgentLogger.Error($"Release {latest} is missing the installer or SHA256.txt; update skipped.");
                return;
            }

            Directory.CreateDirectory(_stateDir);
            installer = Path.Combine(_stateDir, $"SuperWall-Kids-Setup-{latest}.exe");
            checksum = Path.Combine(_stateDir, $"SuperWall-Kids-Setup-{latest}.sha256");
            TryDelete(installer);
            TryDelete(checksum);

            var installerUrl = installerAsset.Value.GetProperty("browser_download_url").GetString();
            var checksumUrl = checksumAsset.Value.GetProperty("browser_download_url").GetString();
            if (string.IsNullOrWhiteSpace(installerUrl) || string.IsNullOrWhiteSpace(checksumUrl))
                return;

            await DownloadAsync(installerUrl, installer, ct);
            if (!IsWindowsExecutable(installer))
            {
                AgentLogger.Error("Downloaded installer failed the Windows executable header check.");
                return;
            }

            var checksumText = await DownloadTextAsync(checksumUrl, ct);
            var expected = checksumText
                .Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();

            await using var hashStream = File.OpenRead(installer);
            var actual = Convert.ToHexString(await SHA256.HashDataAsync(hashStream, ct));
            if (string.IsNullOrWhiteSpace(expected) || !actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            {
                AgentLogger.Error($"SHA256 validation failed for installer {latest}; update skipped.");
                return;
            }

            // Inno Setup /SILENT deliberately keeps its installation progress window visible.
            // The SYSTEM service starts it in the active console session so the child user sees
            // the same automated installer progress UI as a normal update.
            InteractiveProcessLauncher.Start(
                installer,
                "/SILENT /SP- /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS");

            AgentLogger.Info($"Started verified SuperWall Kids installer {current} -> {latest}.");
            installer = null;
            checksum = null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException ex) { AgentLogger.Error("Update network error.", ex); }
        catch (JsonException ex) { AgentLogger.Error("Update release JSON error.", ex); }
        catch (Exception ex) { AgentLogger.Error("Unexpected updater error.", ex); }
        finally
        {
            if (!string.IsNullOrWhiteSpace(installer)) TryDelete(installer);
            if (!string.IsNullOrWhiteSpace(checksum)) TryDelete(checksum);
        }
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
        try
        {
            using var stream = File.OpenRead(path);
            return stream.Length >= 2 && stream.ReadByte() == 'M' && stream.ReadByte() == 'Z';
        }
        catch { return false; }
    }

    private async Task DownloadAsync(string url, string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/3.0");
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await input.CopyToAsync(output, ct);
    }

    private async Task<string> DownloadTextAsync(string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("SuperWall-Kids-Updater/3.0");
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct);
    }

    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }
}
