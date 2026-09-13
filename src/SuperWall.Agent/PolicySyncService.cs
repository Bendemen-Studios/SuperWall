using System.Diagnostics;
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
    private bool _revoked;
    private readonly SearchHistoryCollector _history = new();
    private BlockProxy? _proxy;
    private LocalControlServer? _local;
    private PortableBrowserGuard? _portableBrowsers;
    private AppGuard? _appGuard;
    private AutoUpdater? _updater;
    private long _lastAppliedPolicyVersion = -1;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_stateDir);
        SecurityHardening.Apply();
        NetworkHardening.ClearLegacyMachineEnforcement();
        LoadCached();

        await SyncOnce(stoppingToken);
        if (!_revoked) ApplyPolicy();
        StartLocalServices();

        _updater = new AutoUpdater(_stateDir);
        var nextUpdateCheck = DateTimeOffset.UtcNow;

        while (!stoppingToken.IsCancellationRequested)
        {
            await SyncOnce(stoppingToken);
            SecurityHardening.Apply();
            if (!_revoked) ApplyPolicy();

            if (!_revoked && DateTimeOffset.UtcNow >= nextUpdateCheck)
            {
                await _updater.CheckAndInstallAsync(stoppingToken);
                nextUpdateCheck = DateTimeOffset.UtcNow.AddHours(6);
            }

            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }
    }

    private void StartLocalServices()
    {
        if (_revoked) return;

        if (_local is null)
        {
            _local = new LocalControlServer(() => _policy, ApplyPolicy);
            _local.Start();
        }

        ApplyPortableBrowserPolicy();
        ApplyAppPolicy();
    }

    private void ApplyPortableBrowserPolicy()
    {
        if (_revoked || !_policy.BlockPortableBrowsers)
        {
            _portableBrowsers?.Dispose();
            _portableBrowsers = null;
            return;
        }

        if (_portableBrowsers is null)
        {
            _portableBrowsers = new PortableBrowserGuard();
            _portableBrowsers.Start();
        }
    }

    private void ApplyAppPolicy()
    {
        if (_revoked)
        {
            _appGuard?.Dispose();
            _appGuard = null;
            return;
        }

        _appGuard ??= new AppGuard();
        _appGuard.Apply(_policy);
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
    }

    private string LoadOrCreateDeviceId()
    {
        var file = Path.Combine(_stateDir, "device.id");
        try
        {
            if (File.Exists(file))
            {
                var existing = File.ReadAllText(file).Trim();
                if (!string.IsNullOrWhiteSpace(existing)) return existing;
            }
            var id = $"SW-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}";
            File.WriteAllText(file, id);
            return id;
        }
        catch
        {
            return $"SW-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}";
        }
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
            if (_revoked)
            {
                if (!HasEnrollmentKey()) return;
                _agentToken = "";
            }

            if (string.IsNullOrWhiteSpace(_agentToken))
            {
                await Enroll(ct);
                if (_revoked || string.IsNullOrWhiteSpace(_agentToken)) return;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}");
            request.Headers.Add("X-SuperWall-Agent", _agentToken);
            using var response = await _http.SendAsync(request, ct);

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                ClearRevokedState();
                return;
            }

            if (!response.IsSuccessStatusCode) return;
            var envelope = await response.Content.ReadFromJsonAsync<PolicyEnvelope>(cancellationToken: ct);
            if (envelope is null || envelope.Policy.Version < _policy.Version) return;
            _policy = envelope.Policy;
            SavePolicy();
            ApplyPolicy();
            foreach (var command in envelope.Commands)
            {
                if (!command.Type.Equals("request_history", StringComparison.OrdinalIgnoreCase)) continue;
                await UploadHistory(command.Id, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
    }

    private bool HasEnrollmentKey()
    {
        var key = LoadEnrollmentKey();
        return !string.IsNullOrWhiteSpace(key);
    }

    private void ClearRevokedState()
    {
        _revoked = true;
        _agentToken = "";
        LocalSecrets.Delete("agent-token");

        _proxy?.Dispose();
        _proxy = null;
        BrowserPolicy.ClearEnforcement();
        DownloadGuard.SetEnabled(false, _policy);
        _local?.Dispose();
        _local = null;
        _portableBrowsers?.Dispose();
        _portableBrowsers = null;
        _appGuard?.Dispose();
        _appGuard = null;
    }

    private async Task Enroll(CancellationToken ct)
    {
        var enrollmentKey = LoadEnrollmentKey();
        if (string.IsNullOrWhiteSpace(enrollmentKey)) return;
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_dashboard.TrimEnd('/')}/api/enroll/{Uri.EscapeDataString(_deviceId)}");
        request.Headers.Add("X-SuperWall-Enrollment", enrollmentKey);
        request.Content = JsonContent.Create(new { computerName = Environment.MachineName, osVersion = Environment.OSVersion.VersionString });
        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) return;
        var result = await response.Content.ReadFromJsonAsync<EnrollResponse>(cancellationToken: ct);
        if (result is null || string.IsNullOrWhiteSpace(result.AgentToken)) return;
        if (!LocalSecrets.Save("agent-token", result.AgentToken)) return;
        _agentToken = result.AgentToken;
        _policy = result.Policy ?? new();
        SavePolicy();
        ConsumeEnrollmentKey();
        _revoked = false;
        ApplyPolicy();
        StartLocalServices();
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
        if (_revoked) return;

        var policyChanged = _lastAppliedPolicyVersion != _policy.Version;
        BrowserPolicy.Apply(_policy);

        if (_policy.UrlBlockingEnabled)
        {
            if (_proxy is null)
            {
                var candidate = new BlockProxy(host => PolicyRules.IsDomainBlocked(_policy, host));
                try { candidate.Start(); _proxy = candidate; }
                catch { candidate.Dispose(); }
            }
        }
        else
        {
            _proxy?.Dispose();
            _proxy = null;
        }

        DownloadGuard.SetEnabled(_policy.DownloadsBlocked, _policy);
        ApplyPortableBrowserPolicy();
        ApplyAppPolicy();
        _lastAppliedPolicyVersion = _policy.Version;

        if (policyChanged) RestartManagedBrowsers();
    }

    private static void RestartManagedBrowsers()
    {
        foreach (var name in new[] { "msedge", "chrome", "brave", "vivaldi", "opera" })
        {
            try
            {
                foreach (var process in Process.GetProcessesByName(name))
                {
                    try
                    {
                        if (!WindowsUserScope.IsTargetUserProcess(process)) continue;
                        if (!process.CloseMainWindow()) process.Kill(true);
                        else if (!process.WaitForExit(3000)) process.Kill(true);
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
            }
            catch { }
        }
    }

    private async Task UploadHistory(string requestId, CancellationToken ct)
    {
        if (!_policy.SearchHistoryEnabled || string.IsNullOrWhiteSpace(_dashboard) || string.IsNullOrWhiteSpace(_agentToken) || string.IsNullOrWhiteSpace(requestId)) return;
        var records = _history.Collect(_policy.SearchHistoryRetentionDays);
        var upload = new HistoryUpload { DeviceId = _deviceId, RequestId = requestId, Records = records };
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}/history") { Content = JsonContent.Create(upload) };
        request.Headers.Add("X-SuperWall-Agent", _agentToken);
        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode) return;
    }

    public override void Dispose()
    {
        _proxy?.Dispose();
        _local?.Dispose();
        _portableBrowsers?.Dispose();
        _appGuard?.Dispose();
        _http.Dispose();
        base.Dispose();
    }
}
