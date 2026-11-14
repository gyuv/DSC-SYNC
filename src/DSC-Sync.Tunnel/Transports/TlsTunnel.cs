using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DscSync.Core.Security;

namespace DscSync.Tunnel.Transports;

/// <summary>Creates / persists the self-signed certificate used by the Remote host's TLS listener.</summary>
public static class TunnelCertificate
{
    public static X509Certificate2 LoadOrCreate(string pfxPath)
    {
        if (File.Exists(pfxPath))
        {
            try
            {
                var existing = new X509Certificate2(pfxPath, (string?)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
                if (existing.HasPrivateKey && existing.NotAfter > DateTime.Now.AddDays(30)) return Reimport(existing);
            }
            catch (CryptographicException) { /* regenerate below */ }
        }
        var cert = CreateSelfSigned();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(pfxPath))!);
        File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pfx));
        return Reimport(cert);
    }

    public static X509Certificate2 CreateSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN=DSC-Sync Tunnel ({Environment.MachineName})", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        return Reimport(cert);
    }

    // SChannel on Windows needs a persisted (non-ephemeral) key for server authentication.
    private static X509Certificate2 Reimport(X509Certificate2 cert)
        => new(cert.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
}

internal static class TlsDefaults
{
    // Windows Server 2019 SChannel does not implement TLS 1.3, Windows 10 only experimentally: negotiate the best
    // common version. Security does not depend on the TLS version alone: the pairing proof is bound to the cert.
    public const SslProtocols Protocols = SslProtocols.Tls13 | SslProtocols.Tls12;
}

/// <summary>Remote-host TLS listener (default 0.0.0.0:49155). Each <see cref="ConnectAsync"/> returns the next client.</summary>
public sealed class TlsTunnelServer : ITransportConnector
{
    private readonly IPEndPoint _endpoint;
    private readonly X509Certificate2 _certificate;
    private TcpListener? _listener;

    public TlsTunnelServer(IPEndPoint endpoint, X509Certificate2 certificate)
    {
        _endpoint = endpoint;
        _certificate = certificate;
    }

    public string Kind => TransportKinds.TlsTunnel;
    public bool IsAvailable => true;
    public int BoundPort => (_listener?.LocalEndpoint as IPEndPoint)?.Port ?? _endpoint.Port;

    public void Start()
    {
        if (_listener is not null) return;
        _listener = new TcpListener(_endpoint);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start();
    }

    public async Task<TransportConnection> ConnectAsync(CancellationToken ct)
    {
        Start();
        while (true)
        {
            var client = await _listener!.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            client.NoDelay = true;
            var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            try
            {
                using var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                hsCts.CancelAfter(TimeSpan.FromSeconds(15));
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    EnabledSslProtocols = TlsDefaults.Protocols,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, hsCts.Token).ConfigureAwait(false);
                return new TransportConnection
                {
                    Stream = ssl,
                    Kind = Kind,
                    Peer = $"{client.Client.RemoteEndPoint} {ssl.SslProtocol}",
                    ChannelBinding = PairingHandshake.TlsChannelBinding(_certificate.RawData),
                };
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                await ssl.DisposeAsync().ConfigureAwait(false);
                client.Dispose();
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _listener?.Stop();
        _listener = null;
        return ValueTask.CompletedTask;
    }
}

/// <summary>Local-PC TLS client that dials the Remote VM.</summary>
public sealed class TlsTunnelClient : ITransportConnector
{
    private readonly string _host;
    private readonly int _port;

    public TlsTunnelClient(string host, int port)
    {
        _host = host;
        _port = port;
    }

    public string Kind => TransportKinds.TlsTunnel;
    public bool IsAvailable => !string.IsNullOrWhiteSpace(_host);

    public async Task<TransportConnection> ConnectAsync(CancellationToken ct)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));
            await client.ConnectAsync(_host, _port, cts.Token).ConfigureAwait(false);
            byte[]? serverCert = null;
            var ssl = new SslStream(client.GetStream(), false, (_, cert, _, _) =>
            {
                // Identity is verified by the PIN proof bound to this exact certificate, not by a CA chain.
                serverCert = cert?.GetRawCertData();
                return serverCert is not null;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = _host,
                EnabledSslProtocols = TlsDefaults.Protocols,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token).ConfigureAwait(false);
            return new TransportConnection
            {
                Stream = ssl,
                Kind = Kind,
                Peer = $"{_host}:{_port} {ssl.SslProtocol}",
                ChannelBinding = PairingHandshake.TlsChannelBinding(serverCert!),
            };
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
