using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SuperWall.Agent;

public sealed class LocalControlServer : IDisposable
{
    private const int Port = 18581;
    private readonly HttpListener _listener = new();
    private readonly Func<SuperWall.Contracts.SuperWallPolicy> _getPolicy;
    private readonly Action _applyPolicy;

    public LocalControlServer(Func<SuperWall.Contracts.SuperWallPolicy> getPolicy, Action applyPolicy)
    {
        _getPolicy = getPolicy;
        _applyPolicy = applyPolicy;
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
            var path = ctx.Request.Url?.AbsolutePath;
            if (ctx.Request.HttpMethod == "GET" && path == "/")
            {
                await WriteHtml(ctx);
                return;
            }

            if (ctx.Request.HttpMethod == "GET" && path == "/status")
            {
                await WriteJson(ctx, 200, new
                {
                    downloadsBlocked = _getPolicy().DownloadsBlocked,
                    downloadsUnlocked = DownloadGuard.IsTemporarilyUnlocked(),
                    unlockUntilUtc = DownloadGuard.IsTemporarilyUnlocked() ? DownloadGuard.UnlockUntilUtc : (DateTimeOffset?)null
                });
                return;
            }

            if (ctx.Request.HttpMethod == "POST" && path == "/downloads/unlock")
            {
                if (!IsLocalWindowsAdministrator(ctx))
                {
                    await WriteJson(ctx, 403, new { error = "Windows administrator authentication required." });
                    return;
                }

                // One administrator approval opens downloads only until the next policy-enforced timeout.
                var duration = TimeSpan.FromMinutes(15);
                if (!DownloadGuard.GrantTemporaryUnlock(duration))
                {
                    await WriteJson(ctx, 409, new { error = "Downloads are not currently blocked by policy." });
                    return;
                }

                _applyPolicy();
                await WriteJson(ctx, 200, new
                {
                    downloadsUnlocked = true,
                    unlockUntilUtc = DownloadGuard.UnlockUntilUtc,
                    approvedBy = ctx.User?.Identity?.Name ?? "Windows administrator"
                });
                return;
            }

            if (ctx.Request.HttpMethod == "POST" && path == "/downloads/lock")
            {
                if (!IsLocalWindowsAdministrator(ctx))
                {
                    await WriteJson(ctx, 403, new { error = "Windows administrator authentication required." });
                    return;
                }

                DownloadGuard.RevokeTemporaryUnlock();
                _applyPolicy();
                await WriteJson(ctx, 200, new { downloadsUnlocked = false });
                return;
            }

            ctx.Response.StatusCode = 404;
        }
        finally { ctx.Response.Close(); }
    }

    private async Task WriteHtml(HttpListenerContext ctx)
    {
        var html = """<!doctype html>
<html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SuperWall - Downloads</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:60px auto;padding:24px;background:#f5f5f5;color:#111}main{background:#fff;border-radius:16px;padding:28px;box-shadow:0 8px 30px #0001}button{border:0;border-radius:10px;padding:12px 18px;font-weight:700;cursor:pointer;margin-right:8px}#unlock{background:#111;color:#fff}#lock{background:#ddd}#status{margin:18px 0;font-weight:600}.hint{color:#666;font-size:14px}</style></head>
<body><main><h1>SuperWall</h1><h2>Downloads</h2><div id="status">Status wordt geladen…</div><button id="unlock">Download één keer toestaan</button><button id="lock">Direct weer blokkeren</button><p class="hint">Alleen een Windows-administrator kan dit wijzigen. De toestemming verloopt automatisch na 15 minuten.</p></main>
<script>
const statusEl=document.getElementById('status');
async function status(){try{const r=await fetch('/status',{cache:'no-store'});const x=await r.json();statusEl.textContent=x.downloadsUnlocked?'Downloads tijdelijk toegestaan':'Downloads geblokkeerd';}catch(e){statusEl.textContent='Agent niet bereikbaar';}}
document.getElementById('unlock').onclick=async()=>{const r=await fetch('/downloads/unlock',{method:'POST'});const x=await r.json();if(!r.ok)alert(x.error||'Toestaan mislukt');await status();};
document.getElementById('lock').onclick=async()=>{const r=await fetch('/downloads/lock',{method:'POST'});const x=await r.json();if(!r.ok)alert(x.error||'Blokkeren mislukt');await status();};
status();setInterval(status,5000);
</script></body></html>""";
        var bytes = Encoding.UTF8.GetBytes(html);
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.Response.StatusCode = 200;
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
    }

    private static bool IsLocalWindowsAdministrator(HttpListenerContext ctx)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return false;
            if (ctx.User?.Identity is not WindowsIdentity identity || !identity.IsAuthenticated) return false;
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
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
