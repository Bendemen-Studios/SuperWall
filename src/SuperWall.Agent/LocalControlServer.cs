using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class LocalControlServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly Func<SuperWallPolicy> _getPolicy;
    private int _failedAttempts;
    private DateTimeOffset _lockoutUntilUtc;

    public LocalControlServer(Func<SuperWallPolicy> getPolicy)
    {
        _getPolicy = getPolicy;
        _listener.Prefixes.Add("http://127.0.0.1:18581/");
    }

    public void Start()
    {
        try { _listener.Start(); _ = Loop(); } catch { }
    }

    private async Task Loop()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); } catch { break; }
            _ = Handle(ctx);
        }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            using var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private async Task Handle(HttpListenerContext ctx)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers["Pragma"] = "no-cache";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        try
        {
            if (ctx.Request.HttpMethod == "GET" && ctx.Request.Url?.AbsolutePath == "/status")
            {
                await WriteJson(ctx, 200, new { downloadsUnlocked = DownloadGuard.IsUnlocked() });
                return;
            }

            if (ctx.Request.HttpMethod != "POST" || ctx.Request.Url?.AbsolutePath != "/unlock")
            {
                ctx.Response.StatusCode = 404;
                return;
            }

            if (!IsAdministrator())
            {
                await WriteJson(ctx, 403, new { ok = false, message = "Administrator privileges required." });
                return;
            }

            if (_lockoutUntilUtc > DateTimeOffset.UtcNow)
            {
                await WriteJson(ctx, 429, new { ok = false, message = "Temporarily locked after repeated failures." });
                return;
            }

            string pin = "";
            try
            {
                using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8, leaveOpen: false);
                var body = await reader.ReadToEndAsync();
                pin = JsonDocument.Parse(body).RootElement.GetProperty("pin").GetString() ?? "";
            }
            catch { }

            var policy = _getPolicy();
            var ok = DownloadGuard.Unlock(pin, policy);
            if (ok)
            {
                Interlocked.Exchange(ref _failedAttempts, 0);
                await WriteJson(ctx, 200, new { ok = true, message = "Downloads unlocked for 10 minutes." });
                return;
            }

            var failures = Interlocked.Increment(ref _failedAttempts);
            if (failures >= 5)
            {
                _lockoutUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5);
                Interlocked.Exchange(ref _failedAttempts, 0);
            }
            await WriteJson(ctx, 403, new { ok = false, message = "Invalid PIN." });
        }
        finally { ctx.Response.Close(); }
    }

    private static async Task WriteJson(HttpListenerContext ctx, int status, object value)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.StatusCode = status;
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
    }

    public void Dispose() { try { _listener.Stop(); _listener.Close(); } catch { } }
}
