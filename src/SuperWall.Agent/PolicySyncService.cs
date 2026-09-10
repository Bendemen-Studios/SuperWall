using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class PolicySyncService : BackgroundService
{
    private readonly string _stateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SuperWall");
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private SuperWallPolicy _policy = new();
    private string _deviceId = "";
    private string _dashboard = "";
    private string _agentToken = "";
    private readonly SearchHistoryCollector _history = new();
    private BlockProxy? _proxy;
    private LocalControlServer? _local;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_stateDir);
        LoadCached();
        ApplyPolicy();
        _local = new LocalControlServer();
        _local.Start();
        while (!stoppingToken.IsCancellationRequested)
        {
            await SyncOnce(stoppingToken);
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }
    }

    private void LoadCached()
    {
        var file = Path.Combine(_stateDir, "policy.json");
        try { _policy = JsonSerializer.Deserialize<SuperWallPolicy>(File.ReadAllText(file)) ?? new(); } catch { _policy = new(); }
        _dashboard = Environment.GetEnvironmentVariable("SUPERWALL_DASHBOARD") ?? _policy.DashboardUrl;
        _agentToken = Environment.GetEnvironmentVariable("SUPERWALL_AGENT_TOKEN") ?? "change-me";
        _deviceId = LoadOrCreateDeviceId();
    }

    private string LoadOrCreateDeviceId()
    {
        var file = Path.Combine(_stateDir, "device.id");
        if (File.Exists(file)) return File.ReadAllText(file).Trim();
        var id = $"SW-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}";
        File.WriteAllText(file, id);
        return id;
    }

    private async Task SyncOnce(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_dashboard)) return;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}");
            request.Headers.Add("X-SuperWall-Agent", _agentToken);
            var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) return;
            var envelope = await response.Content.ReadFromJsonAsync<PolicyEnvelope>(cancellationToken: ct);
            if (envelope is null) return;
            _policy = envelope.Policy ?? new();
            File.WriteAllText(Path.Combine(_stateDir, "policy.json"), JsonSerializer.Serialize(_policy, new JsonSerializerOptions { WriteIndented = true }));
            ApplyPolicy();
            foreach (var command in envelope.Commands)
                if (command.Type.Equals("request_history", StringComparison.OrdinalIgnoreCase)) await UploadHistory(ct);
        }
        catch { /* offline-first: keep cached policy */ }
    }

    private void ApplyPolicy()
    {
        BrowserPolicy.Apply(_policy.DownloadsBlocked);
        _proxy?.Dispose();
        if (_policy.UrlBlockingEnabled)
        {
            _proxy = new BlockProxy(IsBlocked);
            _proxy.Start();
        }
        DownloadGuard.SetEnabled(_policy.DownloadsBlocked);
    }

    private bool IsBlocked(string host) => _policy.BlockedDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

    private async Task UploadHistory(CancellationToken ct)
    {
        if (!_policy.SearchHistoryEnabled || string.IsNullOrWhiteSpace(_dashboard)) return;
        var records = _history.Collect(_policy.SearchHistoryRetentionDays);
        if (records.Count == 0) return;
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_dashboard.TrimEnd('/')}/api/agent/{Uri.EscapeDataString(_deviceId)}/history")
        { Content = JsonContent.Create(new HistoryUpload { DeviceId = _deviceId, Records = records }) };
        request.Headers.Add("X-SuperWall-Agent", _agentToken);
        await _http.SendAsync(request, ct);
    }
}
