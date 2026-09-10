using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class PolicySyncService : BackgroundService
{
    private readonly string _stateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");
    private const string EnrollmentFileName = "enrollment.key";
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private SuperWallPolicy _policy = new();
    private string _deviceId = "";
    private string _dashboard = "";
    private string _agentToken = "";
    private readonly SearchHistoryCollector _history = new();
    private BlockProxy? _proxy;
    private LocalControlServer? _local;
    private readonly PortableBrowserGuard _portableBrowsers = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_stateDir);
        SecurityHardening.Apply();
        LoadCached();
        ApplyPolicy();
        _local = new LocalControlServer(() => _policy);
        _local.Start();
        _portableBrowsers.Start();
        while (!stoppingToken.IsCancellationRequested)
        {
            await SyncOnce(stoppingToken);
            SecurityHardening.Apply();
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }
    }

    private void LoadCached()
    {
        var file = Path.Combine(_stateDir, "policy.json");
        try { _policy = JsonSerializer.Deserialize<SuperWallPolicy>(File.ReadAllText(file)) ?? new(); } catch { _policy = new(); }
        _dashboard = Environment.GetEnvironmentVariable("SUPERWALL_DASHBOARD") ?? _policy.DashboardUrl;
        _agentToken = LocalSecrets.Load("agent-token") ?? "";
        _deviceId = LoadOrCreateDeviceId();
        EnsureDefaultPin();
    }

    private void EnsureDefaultPin()
    {
        if (!string.IsNullOrWhiteSpace(_policy.DownloadPinHash) && !string.IsNullOrWhiteSpace(_policy.DownloadPinSalt)) return;
        var (hash, salt) = PinSecurity.CreateHash("2003");
        _policy.DownloadPinHash = hash;
        _policy.DownloadPinSalt = salt;
        SavePolicy();
    }

    private string LoadOrCreateDeviceId()
    {
        var file = Path.Combine(_stateDir, "device.id");
        if (File.Exists(file)) return File.ReadAllText(file).Trim();
        var id = $"SW-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}";
        File.WriteAllText(file, id);
        return id;
    }

    private string? LoadEnrollmentKey()
    {
        try
        {
            var file = Path.Combine(_stateDir, EnrollmentFileName);
            if (!File.Exists(file)) return null;
            return File.ReadAllText(file).Trim();
        }
        catch { return null; }
    }

    private void ConsumeEnrollmentKey()
    {
        try { File.Delete(Path.Combine(_stateDir, EnrollmentFileName)); } catch { }
        try { Environment.SetEnvironmentVariable("SUPERWALL_ENROLLMENT_KEY", null, EnvironmentVariableTarget.Machine); } catch { }
    }

    private async Task SyncOnce(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_dashboard)) return;
        if (!Uri.TryCreate(_dashboard, UriKind.Absolute, out var baseUri) || !string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) return;
        try
        {
            if (string.IsNullOrWhiteSpace(_agentToken)) await Enroll(ct);
            if (string.IsNullOrWhiteSpace(_agentToken)) return;
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}");
            request.Headers.Add("X-SuperWall-Agent", _agentToken);
            var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return;
            var envelope = await response.Content.ReadFromJsonAsync<PolicyEnvelope>(cancellationToken: ct);
            if (envelope is null || envelope.Policy.Version < _policy.Version) return;
            _policy = envelope.Policy;
            EnsureDefaultPin();
            SavePolicy();
            ApplyPolicy();
            foreach (var command in envelope.Commands)
                if (command.Type.Equals("request_history", StringComparison.OrdinalIgnoreCase)) await UploadHistory(ct);
        }
        catch { /* offline-first: retain the last known-good policy */ }
    }

    private async Task Enroll(CancellationToken ct)
    {
        var enrollmentKey = LoadEnrollmentKey();
        if (string.IsNullOrWhiteSpace(enrollmentKey)) return;
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_dashboard.TrimEnd('/')}/api/enroll/{Uri.EscapeDataString(_deviceId)}");
        request.Headers.Add("X-SuperWall-Enrollment", enrollmentKey);
        request.Content = JsonContent.Create(new { computerName = Environment.MachineName, osVersion = Environment.OSVersion.VersionString });
        var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) return;
        var result = await response.Content.ReadFromJsonAsync<EnrollResponse>(cancellationToken: ct);
        if (result is null || string.IsNullOrWhiteSpace(result.AgentToken)) return;
        if (!LocalSecrets.Save("agent-token", result.AgentToken)) return;
        _agentToken = result.AgentToken;
        _policy = result.Policy ?? new();
        EnsureDefaultPin();
        SavePolicy();
        ConsumeEnrollmentKey();
    }

    private void SavePolicy()
    {
        try
        {
            var path = Path.Combine(_stateDir, "policy.json");
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_policy, new JsonSerializerOptions { WriteIndented = true }));
            File.Replace(temp, path, null, true);
        }
        catch { }
    }

    private void ApplyPolicy()
    {
        BrowserPolicy.Apply(_policy);
        _proxy?.Dispose();
        if (_policy.UrlBlockingEnabled)
        {
            _proxy = new BlockProxy(IsBlocked);
            _proxy.Start();
        }
        NetworkHardening.Apply(_policy.BlockedDomains, _policy.UrlBlockingEnabled);
        DownloadGuard.SetEnabled(_policy.DownloadsBlocked, _policy);
    }

    private bool IsBlocked(string host) => _policy.BlockedDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

    private async Task UploadHistory(CancellationToken ct)
    {
        if (!_policy.SearchHistoryEnabled || string.IsNullOrWhiteSpace(_dashboard) || string.IsNullOrWhiteSpace(_agentToken)) return;
        var records = _history.Collect(_policy.SearchHistoryRetentionDays);
        if (records.Count == 0) return;
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}/history")
        { Content = JsonContent.Create(new HistoryUpload { DeviceId = _deviceId, Records = records }) };
        request.Headers.Add("X-SuperWall-Agent", _agentToken);
        await _http.SendAsync(request, ct);
    }

    public override void Dispose()
    {
        _proxy?.Dispose();
        _local?.Dispose();
        _portableBrowsers.Dispose();
        _http.Dispose();
        base.Dispose();
    }
}
