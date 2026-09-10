using System.Net;
using System.Text.Json;
using SuperWall.Contracts;

namespace SuperWall.Agent;

public sealed class LocalControlServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly Func<SuperWallPolicy> _getPolicy;

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

    private async Task Handle(HttpListenerContext ctx)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        try
        {
            if (ctx.Request.HttpMethod == "POST" && ctx.Request.Url?.AbsolutePath == "/unlock")
            {
                using var reader = new StreamReader(ctx.Request.InputStream);
                var body = await reader.ReadToEndAsync();
                string pin = "";
                try { pin = JsonDocument.Parse(body).RootElement.GetProperty("pin").GetString() ?? ""; } catch { }
                var ok = DownloadGuard.Unlock(pin, _getPolicy());
                await WriteJson(ctx, ok ? 200 : 403, new { ok, message = ok ? "Downloads unlocked for 10 minutes." : "Invalid PIN." });
                return;
            }
            if (ctx.Request.HttpMethod == "GET" && ctx.Request.Url?.AbsolutePath == "/status")
            {
                await WriteJson(ctx, 200, new { downloadsUnlocked = DownloadGuard.IsUnlocked() });
                return;
            }
            ctx.Response.StatusCode = 404;
        }
        finally { ctx.Response.Close(); }
    }

    private static async Task WriteJson(HttpListenerContext ctx, int status, object value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));
        ctx.Response.ContentType = "application/json";
        ctx.Response.StatusCode = status;
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
    }

    public void Dispose() { try { _listener.Stop(); _listener.Close(); } catch { } }
}
