using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SuperWall.Agent;

public sealed class BlockProxy : IDisposable
{
    private const int MaxHeaderBytes = 65536;
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
        if (_cts is not null) return;
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
        using var stream = client.GetStream();

        var request = await ReadHeadersAsync(stream, ct);
        if (request is null) return;

        var firstLine = request.Value.HeaderText.Split("\r\n", 2, StringSplitOptions.None)[0];
        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return;

        var connect = parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase);
        string host;
        int port;
        if (connect)
        {
            if (!TryParseHostPort(parts[1], 443, out host, out port)) return;
        }
        else
        {
            if (!Uri.TryCreate(parts[1], UriKind.Absolute, out var requestUri)) return;
            host = requestUri.Host;
            port = requestUri.Port > 0 ? requestUri.Port : 80;
        }

        if (string.IsNullOrWhiteSpace(host) || _isBlocked(host))
        {
            await Deny(stream, ct);
            return;
        }

        using var upstream = new TcpClient();
        try { await upstream.ConnectAsync(host, port, ct); }
        catch { return; }
        using var upstreamStream = upstream.GetStream();

        if (connect)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct);
        }
        else
        {
            await upstreamStream.WriteAsync(request.Value.Bytes, ct);
        }

        var downstream = stream.CopyToAsync(upstreamStream, ct);
        var upstreamCopy = upstreamStream.CopyToAsync(stream, ct);
        await Task.WhenAny(downstream, upstreamCopy);
    }

    private static async Task<(byte[] Bytes, string HeaderText)?> ReadHeadersAsync(NetworkStream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        while (ms.Length < MaxHeaderBytes)
        {
            var read = await stream.ReadAsync(buffer, ct);
            if (read <= 0) return null;
            ms.Write(buffer, 0, read);
            var data = ms.ToArray();
            var headerEnd = FindHeaderEnd(data);
            if (headerEnd < 0) continue;
            return (data, Encoding.ASCII.GetString(data, 0, headerEnd));
        }
        return null;
    }

    private static int FindHeaderEnd(byte[] data)
    {
        for (var i = 3; i < data.Length; i++)
            if (data[i - 3] == '\r' && data[i - 2] == '\n' && data[i - 1] == '\r' && data[i] == '\n')
                return i + 1;
        return -1;
    }

    private static bool TryParseHostPort(string value, int defaultPort, out string host, out int port)
    {
        host = "";
        port = defaultPort;
        try
        {
            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                var end = value.IndexOf(']');
                if (end < 0) return false;
                host = value[1..end];
                if (end + 1 < value.Length && value[end + 1] == ':' && !int.TryParse(value[(end + 2)..], out port)) return false;
            }
            else
            {
                var colon = value.LastIndexOf(':');
                if (colon > 0 && int.TryParse(value[(colon + 1)..], out var parsed))
                {
                    host = value[..colon];
                    port = parsed;
                }
                else host = value;
            }
            return !string.IsNullOrWhiteSpace(host) && port is > 0 and <= 65535;
        }
        catch { return false; }
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
        _cts = null;
    }
}
