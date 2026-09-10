using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SuperWall.Contracts;

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
            var buffer = new byte[8192];
            int read = await stream.ReadAsync(buffer, ct);
            if (read <= 0) return;
            var header = Encoding.ASCII.GetString(buffer, 0, read);
            var first = header.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            var parts = first.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return;

            string host;
            bool connect = parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase);
            if (connect)
                host = parts[1].Split(':')[0];
            else
            {
                try { host = new Uri(parts[1]).Host; }
                catch { return; }
            }

            if (_isBlocked(host))
            {
                var response = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), ct);
                return;
            }

            if (!connect) return; // Only CONNECT tunnelling is supported for safe HTTPS proxying.

            using var upstream = new TcpClient();
            try { await upstream.ConnectAsync(host, 443, ct); }
            catch { return; }
            using var upstreamStream = upstream.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct);
            var t1 = stream.CopyToAsync(upstreamStream, ct);
            var t2 = upstreamStream.CopyToAsync(stream, ct);
            await Task.WhenAny(t1, t2);
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _listener.Stop(); } catch { }
        _cts?.Dispose();
    }
}
