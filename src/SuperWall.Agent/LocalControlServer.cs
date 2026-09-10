using System.Net;
using System.Text.Json;

namespace SuperWall.Agent;

public sealed class LocalControlServer : IDisposable
{
    private readonly HttpListener _listener = new();
    public LocalControlServer()
    {
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
    private static async Task Handle(HttpListenerContext ctx)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        if (ctx.Request.HttpMethod == "POST" && ctx.Request.Url?.AbsolutePath == "/unlock")
        {
            using var reader = new StreamReader(ctx.Request.InputStream);
            var body = await reader.ReadToEndAsync();
            string pin = "";
            try { pin = JsonDocument.Parse(body).RootElement.GetProperty("pin").GetString() ?? ""; } catch { }
            var ok = DownloadGuard.Unlock(pin);
            var bytes = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { ok, message = ok ? "Downloads unlocked for 10 minutes." : "Invalid PIN." }));
            ctx.Response.ContentType = "application/json"; ctx.Response.StatusCode = ok ? 200 : 403; ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes); ctx.Response.Close(); return;
        }
        ctx.Response.StatusCode = 404; ctx.Response.Close();
    }
    public void Dispose(){try{_listener.Stop();_listener.Close();}catch{}}
}
