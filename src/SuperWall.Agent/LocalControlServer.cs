using System.Net;
using System.Text.Json;

namespace SuperWall.Agent;

public sealed class LocalControlServer : IDisposable
{
    private const int Port = 18581;
    private readonly HttpListener _listener = new();

    public LocalControlServer(Func<SuperWall.Contracts.SuperWallPolicy> getPolicy)
    {
        _listener.AuthenticationSchemes = AuthenticationSchemes.IntegratedWindowsAuthentication;
        _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
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
        ctx.Response.Headers["Pragma"] = "no-cache";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        try
        {
            // Local download unlocking has been removed.
            // Download blocking is controlled exclusively by the central admin dashboard.
            if (ctx.Request.HttpMethod == "GET" && ctx.Request.Url?.AbsolutePath == "/status")
            {
                await WriteJson(ctx, 200, new { downloadsUnlocked = false, downloadControl = "dashboard" });
                return;
            }

            ctx.Response.StatusCode = 404;
        }
        finally { ctx.Response.Close(); }
    }

    private static async Task WriteJson(HttpListenerContext ctx, int status, object value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.StatusCode = status;
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
    }

    public void Dispose() { try { _listener.Stop(); _listener.Close(); } catch { } }
}
