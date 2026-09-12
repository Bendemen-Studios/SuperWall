using System.Net;
using System.Security.Principal;
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
            if (ctx.Request.HttpMethod == "GET" && ctx.Request.Url?.AbsolutePath == "/status")
            {
                await WriteJson(ctx, 200, new
                {
                    downloadsBlocked = _getPolicy().DownloadsBlocked,
                    downloadsUnlocked = DownloadGuard.IsTemporarilyUnlocked(),
                    unlockUntilUtc = DownloadGuard.IsTemporarilyUnlocked() ? DownloadGuard.UnlockUntilUtc : (DateTimeOffset?)null
                });
                return;
            }

            if (ctx.Request.HttpMethod == "POST" && ctx.Request.Url?.AbsolutePath == "/downloads/unlock")
            {
                if (!IsLocalWindowsAdministrator(ctx))
                {
                    await WriteJson(ctx, 403, new { error = "Windows administrator authentication required." });
                    return;
                }

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

            if (ctx.Request.HttpMethod == "POST" && ctx.Request.Url?.AbsolutePath == "/downloads/lock")
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

    private static bool IsLocalWindowsAdministrator(HttpListenerContext ctx)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return false;
            if (ctx.User?.Identity is not System.Security.Principal.WindowsIdentity identity || !identity.IsAuthenticated) return false;
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
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
