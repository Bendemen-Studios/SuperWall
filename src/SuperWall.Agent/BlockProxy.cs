using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SuperWall.Agent;

public sealed class BlockProxy : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<string, bool> _isBlocked;
    private CancellationTokenSource? _cts;

    public BlockProxy(Func<string, bool> isBlocked, int port = 18580)
    {
        _isBlocked = isBlocked;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listener.Start();
        _ = AcceptLoop(_cts.Token);
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct); }
            catch { break; }
            _ = Handle(client, ct);
        }
    }

    private async Task Handle(TcpClient client, CancellationToken ct)
    {
        using (client)
        using (NetworkStream stream = client.GetStream())
        {
            var buffer = new byte[16384];
            int read = await stream.ReadAsync(buffer, ct);
            if (read <= 0) return;

            var header = Encoding.ASCII.GetString(buffer, 0, read);
            var first = header.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            var parts = first.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return;

            var connect = parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase);
            string host;
            Uri? requestUri = null;

            if (connect) host = parts[1].Split(':')[0];
            else
            {
                try { requestUri = new Uri(parts[1], UriKind.Absolute); host = requestUri.Host; }
                catch { return; }
            }

            if (_isBlocked(host)) { await Deny(stream, ct); return; }

            if (connect)
            {
                using var upstream = new TcpClient();
                try { await upstream.ConnectAsync(host, 443, ct); } catch { return; }
                using var upstreamStream = upstream.GetStream();
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct);
                var t1 = stream.CopyToAsync(upstreamStream, ct);
                var t2 = upstreamStream.CopyToAsync(stream, ct);
                await Task.WhenAny(t1, t2);
                return;
            }

            using var httpUpstream = new TcpClient();
            try { await httpUpstream.ConnectAsync(host, requestUri!.Port > 0 ? requestUri.Port : 80, ct); } catch { return; }
            using var httpStream = httpUpstream.GetStream();
            await httpStream.WriteAsync(buffer.AsMemory(0, read), ct);

            using var ms = new MemoryStream();
            var temp = new byte[8192];
            while (ms.Length < 32768)
            {
                var n = await httpStream.ReadAsync(temp, ct);
                if (n <= 0) break;
                ms.Write(temp, 0, n);
                var current = Encoding.ASCII.GetString(ms.GetBuffer(), 0, (int)ms.Length);
                if (current.Contains("\r\n\r\n", StringComparison.Ordinal)) break;
            }

            var responseBytes = ms.ToArray();
            var location = GetHeader(Encoding.ASCII.GetString(responseBytes), "Location");
            if (!string.IsNullOrWhiteSpace(location))
            {
                try
                {
                    var target = new Uri(requestUri!, location);
                    if (_isBlocked(target.Host)) { await Deny(stream, ct); return; }
                }
                catch { }
            }

            await stream.WriteAsync(responseBytes, ct);
            var t3 = httpStream.CopyToAsync(stream, ct);
            var t4 = stream.CopyToAsync(httpStream, ct);
            await Task.WhenAny(t3, t4);
        }
    }

    private static string? GetHeader(string headers, string name)
    {
        foreach (var line in headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            if (line[..colon].Equals(name, StringComparison.OrdinalIgnoreCase)) return line[(colon + 1)..].Trim();
        }
        return null;
    }

    private static async Task Deny(NetworkStream stream, CancellationToken ct)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"), ct);
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _listener.Stop(); } catch { }
        _cts?.Dispose();
    }
}
