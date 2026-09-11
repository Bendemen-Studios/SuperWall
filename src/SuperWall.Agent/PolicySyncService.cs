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
    private const string DashboardFileName = "dashboard.url";
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private SuperWallPolicy _policy = new();
    private string _deviceId = "";
    private string _dashboard = "";
    private string _agentToken = "";
    private readonly SearchHistoryCollector _history = new();
    private BlockProxy? _proxy;
    private LocalControlServer? _local;
    private readonly PortableBrowserGuard _portableBrowsers = new();
    private AutoUpdater? _updater;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_stateDir);
        SecurityHardening.Apply();
        LoadCached();
        ApplyPolicy();
        _local = new LocalControlServer(() => _policy);
        _local.Start();
        _portableBrowsers.Start();
        _updater = new AutoUpdater(_stateDir);
        var nextUpdateCheck = DateTimeOffset.UtcNow;

        while (!stoppingToken.IsCancellationRequested)
        {
            await SyncOnce(stoppingToken);
            SecurityHardening.Apply();

            if (DateTimeOffset.UtcNow >= nextUpdateCheck)
            {
                await _updater.CheckAndInstallAsync(stoppingToken);
                nextUpdateCheck = DateTimeOffset.UtcNow.AddHours(6);
            }

            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }
    }

    private void LoadCached()
    {
        var file = Path.Combine(_stateDir, "policy.json");
        try { _policy = JsonSerializer.Deserialize<SuperWallPolicy>(File.ReadAllText(file)) ?? new(); } catch { _policy = new(); }
        var dashboardFile = Path.Combine(_stateDir, DashboardFileName);
        var configured = "";
        try { if (File.Exists(dashboardFile)) configured = File.ReadAllText(dashboardFile).Trim(); } catch { }
        _dashboard = string.IsNullOrWhiteSpace(configured) ? (Environment.GetEnvironmentVariable("SUPERWALL_DASHBOARD") ?? _policy.DashboardUrl) : configured;
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
        try { var file = Path.Combine(_stateDir, EnrollmentFileName); return File.Exists(file) ? File.ReadAllText(file).Trim() : null; } catch { return null; }
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
            {
                if (!command.Type.Equals("request_history", StringComparison.OrdinalIgnoreCase)) continue;
                await UploadHistory(command.Id, ct);
            }
        }
        catch { }
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

        if (_policy.UrlBlockingEnabled)
        {
            // Never let a proxy bind failure kill the Windows service. The next
            // policy sync will retry while the browser remains fail-closed.
            if (_proxy is null)
            {
                var candidate = new BlockProxy(IsBlocked);
                try
                {
                    candidate.Start();
                    _proxy = candidate;
                }
                catch
                {
                    candidate.Dispose();
                }
            }
        }
        else
        {
            _proxy?.Dispose();
            _proxy = null;
        }

        NetworkHardening.Apply(_policy.BlockedDomains, _policy.UrlBlockingEnabled);
        DownloadGuard.SetEnabled(_policy.DownloadsBlocked, _policy);
    }

    private bool IsBlocked(string host) => _policy.BlockedDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

    private async Task UploadHistory(string requestId, CancellationToken ct)
    {
        if (!_policy.SearchHistoryEnabled || string.IsNullOrWhiteSpace(_dashboard) || string.IsNullOrWhiteSpace(_agentToken) || string.IsNullOrWhiteSpace(requestId)) return;
        var records = _history.Collect(_policy.SearchHistoryRetentionDays);
        var upload = new HistoryUpload { DeviceId = _deviceId, RequestId = requestId, Records = records };
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}/history") { Content = JsonContent.Create(upload) };
        request.Headers.Add("X-SuperWall-Agent", _agentToken);
        await _http.SendAsync(request, ct);
    }

    public override void Dispose()
    {
        _proxy?.Dispose(); _local?.Dispose(); _portableBrowsers.Dispose(); _http.Dispose(); base.Dispose();
    }
}
