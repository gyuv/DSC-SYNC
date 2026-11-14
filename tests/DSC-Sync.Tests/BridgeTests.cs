using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DscSync.Core.Pkcs11;
using DscSync.Core.Protocol;
using DscSync.Pkcs11Bridge;
using DscSync.Pkcs11Bridge.Backends;
using DscSync.Pkcs11Bridge.Crypto;
using DscSync.Pkcs11Bridge.Pdf;
using DscSync.Pkcs11Bridge.Simulation;
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using Xunit;

namespace DscSync.Tests;

public class BridgeTests
{
    private static VirtualP11Core NewP11(LinkedPair pair) =>
        new(() => new PipeP11Channel(pair.P11Pipe), ulongSize: 8) { RefreshIntervalMs = 0 };

    private static byte[] U8(ulong v) => BitConverter.GetBytes(v);

    private static ulong FindPrivateKey(VirtualP11Core p11, ulong session)
    {
        Assert.Equal(CKR.OK, p11.FindObjectsInit(session, new[] { new P11Attribute(CKA.CLASS, U8(CKO.PRIVATE_KEY)) }));
        Assert.Equal(CKR.OK, p11.FindObjects(session, 10, out var keys));
        Assert.Equal(CKR.OK, p11.FindObjectsFinal(session));
        return Assert.Single(keys);
    }

    [Fact]
    public async Task TokenState_IsMirroredToRemote()
    {
        using var token = MockToken.Create("RAJESH KUMAR", "EP-1001");
        await using var pair = await LinkedPair.CreateAsync(token);
        await pair.WaitLinkedAsync();
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(10));
        var t = pair.Remote.State.Tokens[0];
        Assert.Equal("EP-1001", t.SerialNumber);
        var cert = Assert.Single(t.Certificates);
        Assert.Equal("RAJESH KUMAR", cert.SubjectCommonName);
        Assert.Equal("Demo Enterprises Pvt Ltd", cert.Organization);
        Assert.StartsWith("eMudhra", cert.IssuerCommonName);
        Assert.True(cert.NotAfter > DateTime.UtcNow);
    }

    [Fact]
    public async Task HotSwap_IsPushedToRemoteInUnderOneSecond_AndP11SeesNewCertificate()
    {
        using var first = MockToken.Create("FIRST HOLDER", "EP-2001");
        using var second = MockToken.Create("SECOND HOLDER", "WD-2002", vendor: "ProxKey (Simulated)", pin: "4321");
        await using var pair = await LinkedPair.CreateAsync(first);
        await pair.WaitLinkedAsync();
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(10));

        using var p11 = NewP11(pair);
        Assert.Equal(CKR.OK, p11.Initialize());
        Assert.Equal(CKR.OK, p11.OpenSession(1, CKF.SERIAL_SESSION, out var oldSession));
        Assert.Equal(CKR.OK, p11.Login(oldSession, CKU.USER, first.Pin));

        var events = new List<TokenEventKind>();
        pair.Remote.TokenEvent += e => { lock (events) events.Add(e.Kind); };

        // Unplug the first token.
        var sw = Stopwatch.StartNew();
        pair.Backend.Remove("EP-2001");
        pair.Tokens.RequestRescan(reload: false);
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 0, TimeSpan.FromSeconds(1));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"TOKEN_REMOVED took {sw.ElapsedMilliseconds} ms");

        // The stale session must not be usable any more.
        var stale = p11.GetSessionInfo(oldSession, out _);
        Assert.True(stale is CKR.DEVICE_REMOVED or CKR.SESSION_HANDLE_INVALID, $"stale session returned 0x{stale:X}");
        Assert.Equal(CKR.OK, p11.WaitForSlotEvent(dontBlock: true, out var evSlot));
        Assert.Equal(1UL, evSlot);

        // Plug in a different vendor's token.
        sw.Restart();
        pair.Backend.Insert(second);
        pair.Tokens.RequestRescan(reload: true);
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(1));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"TOKEN_INSERTED took {sw.ElapsedMilliseconds} ms");
        Assert.Equal("SECOND HOLDER", pair.Remote.State.Tokens[0].Certificates[0].SubjectCommonName);
        lock (events)
        {
            Assert.Contains(TokenEventKind.TokenRemoved, events);
            Assert.Contains(TokenEventKind.TokenInserted, events);
        }

        Assert.Equal(CKR.OK, p11.GetTokenInfo(1, out var info));
        Assert.Equal("SECOND HOLDER", info.Label);
        Assert.Equal(CKR.OK, p11.OpenSession(1, CKF.SERIAL_SESSION, out var s));
        Assert.Equal(CKR.OK, p11.Login(s, CKU.USER, second.Pin));
        var key = FindPrivateKey(p11, s);
        Assert.Equal(CKR.OK, p11.SignInit(s, CKM.SHA256_RSA_PKCS, null, key));
        var data = Encoding.UTF8.GetBytes("GST return payload");
        Assert.Equal(CKR.OK, p11.Sign(s, data, out var sig));
        using var cert = second.Certificate;
        Assert.True(cert.GetRSAPublicKey()!.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Equal(CKR.OK, p11.Finalize());
    }

    [Theory]
    [InlineData(CKM.SHA1_RSA_PKCS)]
    [InlineData(CKM.SHA256_RSA_PKCS)]
    [InlineData(CKM.SHA384_RSA_PKCS)]
    [InlineData(CKM.SHA512_RSA_PKCS)]
    [InlineData(CKM.SHA256_RSA_PKCS_PSS)]
    [InlineData(CKM.SHA512_RSA_PKCS_PSS)]
    [InlineData(CKM.RSA_PKCS)]
    [InlineData(CKM.RSA_PKCS_PSS)]
    public async Task VirtualP11_SignRoundTrip_AllMechanisms(ulong mechanism)
    {
        using var token = MockToken.Create("SIGNER", "EP-3001");
        await using var pair = await LinkedPair.CreateAsync(token);
        await pair.WaitLinkedAsync();
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(10));

        using var p11 = NewP11(pair);
        Assert.Equal(CKR.OK, p11.Initialize());
        Assert.Equal(CKR.OK, p11.GetSlotList(true, out var slots));
        Assert.Equal(new ulong[] { 1 }, slots);
        Assert.Equal(CKR.OK, p11.GetMechanismList(1, out var mechs));
        Assert.Contains(mechanism, mechs);
        Assert.Equal(CKR.OK, p11.OpenSession(1, CKF.SERIAL_SESSION, out var s));

        // Private key is invisible before login, certificate is visible.
        Assert.Equal(CKR.OK, p11.FindObjectsInit(s, new[] { new P11Attribute(CKA.CLASS, U8(CKO.PRIVATE_KEY)) }));
        Assert.Equal(CKR.OK, p11.FindObjects(s, 10, out var none));
        Assert.Empty(none);
        p11.FindObjectsFinal(s);
        Assert.Equal(CKR.OK, p11.FindObjectsInit(s, new[] { new P11Attribute(CKA.CLASS, U8(CKO.CERTIFICATE)) }));
        Assert.Equal(CKR.OK, p11.FindObjects(s, 10, out var certs));
        p11.FindObjectsFinal(s);
        Assert.Equal(CKR.OK, p11.GetAttributeValue(s, Assert.Single(certs), CKA.VALUE, out var der));
        Assert.Equal(token.CertificateDer, der);

        Assert.Equal(CKR.PIN_INCORRECT, p11.Login(s, CKU.USER, "0000"));
        Assert.Equal(CKR.OK, p11.Login(s, CKU.USER, token.Pin));
        var key = FindPrivateKey(p11, s);
        Assert.Equal(CKR.ATTRIBUTE_SENSITIVE, p11.GetAttributeValue(s, key, CKA.VALUE, out _));

        var message = RandomNumberGenerator.GetBytes(1000);
        var hash = SHA256.HashData(message);
        byte[] input = mechanism switch
        {
            CKM.RSA_PKCS => DigestInfo.Encode(HashAlgorithmName.SHA256, hash),
            CKM.RSA_PKCS_PSS => hash,
            _ => message,
        };
        var pss = mechanism switch
        {
            CKM.RSA_PKCS_PSS or CKM.SHA256_RSA_PKCS_PSS => DigestInfo.PssFor(HashAlgorithmName.SHA256),
            CKM.SHA512_RSA_PKCS_PSS => DigestInfo.PssFor(HashAlgorithmName.SHA512),
            _ => null,
        };
        Assert.Equal(CKR.OK, p11.SignInit(s, mechanism, pss, key));
        Assert.Equal(CKR.OK, p11.SignatureLength(s, out var len));
        Assert.Equal(256, len);
        Assert.Equal(CKR.OK, p11.Sign(s, input, out var sig));
        Assert.Equal(256, sig.Length);

        using var pub = token.Certificate.GetRSAPublicKey()!;
        bool ok = mechanism switch
        {
            CKM.RSA_PKCS => pub.VerifyHash(hash, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            CKM.RSA_PKCS_PSS => pub.VerifyHash(hash, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            CKM.SHA1_RSA_PKCS => pub.VerifyData(message, sig, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1),
            CKM.SHA256_RSA_PKCS => pub.VerifyData(message, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            CKM.SHA384_RSA_PKCS => pub.VerifyData(message, sig, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            CKM.SHA512_RSA_PKCS => pub.VerifyData(message, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            CKM.SHA256_RSA_PKCS_PSS => pub.VerifyData(message, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            CKM.SHA512_RSA_PKCS_PSS => pub.VerifyData(message, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            _ => false,
        };
        Assert.True(ok);
    }

    [Fact]
    public async Task VirtualP11_MultiPartSign_And_ReloginAfterMiddlewareReload()
    {
        using var token = MockToken.Create("MULTI", "EP-4001");
        await using var pair = await LinkedPair.CreateAsync(token);
        await pair.WaitLinkedAsync();
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(10));
        using var p11 = NewP11(pair);
        p11.Initialize();
        p11.OpenSession(1, CKF.SERIAL_SESSION, out var s);
        Assert.Equal(CKR.OK, p11.Login(s, CKU.USER, token.Pin));
        var key = FindPrivateKey(p11, s);

        // Middleware reload on the Local PC (e.g. another USB device was plugged) drops the vendor login;
        // the bridge transparently logs in again with the cached PIN.
        pair.Backend.Reload();

        Assert.Equal(CKR.OK, p11.SignInit(s, CKM.SHA256_RSA_PKCS, null, key));
        Assert.Equal(CKR.OK, p11.SignUpdate(s, Encoding.UTF8.GetBytes("part-1|")));
        Assert.Equal(CKR.OK, p11.SignUpdate(s, Encoding.UTF8.GetBytes("part-2")));
        Assert.Equal(CKR.OK, p11.Sign(s, null, out var sig));
        Assert.True(token.Certificate.GetRSAPublicKey()!.VerifyData(Encoding.UTF8.GetBytes("part-1|part-2"), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public async Task VirtualP11_ReportsEmptyReaderWhenTunnelIsDown()
    {
        using var token = MockToken.Create("OFFLINE", "EP-5001");
        await using var pair = await LinkedPair.CreateAsync(token);
        await pair.WaitLinkedAsync();
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(10));
        using var p11 = NewP11(pair);
        p11.Initialize();
        await pair.Local.DisposeAsync();
        await TestUtil.WaitUntilAsync(() => !pair.Remote.IsConnected && pair.Remote.State.Tokens.Count == 0, TimeSpan.FromSeconds(10));
        Assert.Equal(CKR.OK, p11.GetSlotList(true, out var present));
        Assert.Empty(present);
        Assert.Equal(CKR.OK, p11.GetSlotList(false, out var all));
        Assert.Single(all);
        Assert.Equal(CKR.TOKEN_NOT_PRESENT, p11.GetTokenInfo(1, out _));
    }

    [Fact]
    public async Task WrongPairingPin_NeverLinks()
    {
        using var token = MockToken.Create("X", "EP-6001");
        await using var pair = await LinkedPair.CreateAsync(token, remotePin: "999999");
        await Task.Delay(1500);
        Assert.False(pair.Remote.IsConnected);
        Assert.Empty(pair.Remote.State.Tokens);
    }

    [Fact]
    public async Task PortProxy_ForwardsBidirectionalTraffic_AndResetsOnTokenSwap()
    {
        // Fake "emSigner" on the Local PC: a line-based echo server.
        var emSigner = new TcpListener(IPAddress.Loopback, 0);
        emSigner.Start();
        int emSignerPort = ((IPEndPoint)emSigner.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await emSigner.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(async () =>
                {
                    using var _c = c;
                    var s = c.GetStream();
                    var buf = new byte[4096];
                    int n;
                    try { while ((n = await s.ReadAsync(buf)) > 0) await s.WriteAsync(Encoding.UTF8.GetBytes("emSigner:" + Encoding.UTF8.GetString(buf, 0, n))); }
                    catch (IOException) { }
                });
            }
        });

        int proxyPort = TestUtil.FreeTcpPort();
        using var token = MockToken.Create("PORTS", "EP-7001");
        await using var pair = await LinkedPair.CreateAsync(token, new List<int> { proxyPort }, p => p == proxyPort ? emSignerPort : p);
        await pair.WaitLinkedAsync();
        Assert.Contains(pair.Remote.PortStatus, s => s.Port == proxyPort && s.State == DscSync.Tunnel.Proxy.PortState.Listening);

        using var browser = new TcpClient();
        await browser.ConnectAsync(IPAddress.Loopback, proxyPort);
        var bs = browser.GetStream();
        for (int i = 0; i < 3; i++)
        {
            await bs.WriteAsync(Encoding.UTF8.GetBytes($"msg{i}"));
            var buf = new byte[256];
            int n = await bs.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal($"emSigner:msg{i}", Encoding.UTF8.GetString(buf, 0, n));
        }

        // Token swap kills stale keep-alive connections so the portal reconnects and sees the new certificate.
        pair.Backend.Remove("EP-7001");
        pair.Tokens.RequestRescan(false);
        var rb = new byte[16];
        int closed = await bs.ReadAsync(rb).AsTask().WaitAsync(TimeSpan.FromSeconds(5)).ContinueWith(t => t.IsFaulted ? 0 : t.Result);
        Assert.Equal(0, closed);
        emSigner.Stop();
    }

    [Fact]
    public async Task PortProxy_RefusesWhenLocalIsNotLinked()
    {
        int proxyPort = TestUtil.FreeTcpPort();
        await using var proxy = new DscSync.Tunnel.Proxy.LoopbackPortProxy(() => null);
        proxy.Start(new[] { proxyPort });
        using var c = new TcpClient();
        await c.ConnectAsync(IPAddress.Loopback, proxyPort);
        var buf = new byte[4];
        int n = await c.GetStream().ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, n);
    }

    [Fact]
    public async Task LocalPortTarget_OnlyOpensAllowedPorts()
    {
        var target = new DscSync.Tunnel.Proxy.LocalPortTarget(new[] { 1585 });
        Assert.Null(await target.OpenAsync(22, CancellationToken.None));
    }

    [Fact]
    public async Task PdfSigner_SignsThroughRemoteToken_AndSignatureVerifies()
    {
        using var token = MockToken.Create("PDF SIGNER", "EP-8001");
        await using var pair = await LinkedPair.CreateAsync(token);
        await pair.WaitLinkedAsync();
        await TestUtil.WaitUntilAsync(() => pair.Remote.State.Tokens.Count == 1, TimeSpan.FromSeconds(10));

        var dir = Directory.CreateTempSubdirectory("dscsync-pdf");
        var input = Path.Combine(dir.FullName, "in.pdf");
        var output = Path.Combine(dir.FullName, "out.pdf");
        using (var writer = new PdfWriter(input))
        using (var pdf = new PdfDocument(writer))
        using (var doc = new Document(pdf))
        {
            doc.Add(new Paragraph("MCA V3 form - page 1"));
            pdf.AddNewPage();
            doc.Add(new Paragraph("page 2"));
        }

        var t = pair.Remote.State.Tokens[0];
        var c = t.Certificates[0];
        await pair.Remote.LoginAsync(t.SlotId, pair.Remote.State.Generation, token.Pin);
        using var rsa = new TokenRsa(pair.Remote, t, c);
        using var x509 = new X509Certificate2(c.Der);
        var result = PdfSigningService.Sign(input, output, x509, rsa, new PdfSignOptions { PageNumber = 2, Reason = "Test", Location = "Chennai" });
        Assert.Equal(2, result.Page);
        Assert.Equal("PDF SIGNER", result.SignerName);

        var verification = PdfSigningService.Verify(output);
        var v = Assert.Single(verification);
        Assert.True(v.Valid);
        Assert.Equal("PDF SIGNER", v.Signer);
        Assert.Equal(1, pair.Backend.SignCount);
        dir.Delete(true);
    }

    [Fact]
    public void TokenRsa_RefusesPrivateExport()
    {
        using var token = MockToken.Create("RSA", "EP-9001");
        var backend = new MockTokenBackend();
        backend.Insert(token);
        using var mgr = new TokenManager(backend);
        mgr.Rescan(true);
        var t = mgr.State.Tokens[0];
        using var rsa = new TokenRsa(mgr, t, t.Certificates[0]);
        Assert.Throws<CryptographicException>(() => rsa.ExportParameters(true));
        Assert.Equal(2048, rsa.KeySize);
        mgr.LoginAsync(t.SlotId, mgr.State.Generation, token.Pin).GetAwaiter().GetResult();
        var hash = SHA384.HashData(Encoding.UTF8.GetBytes("abc"));
        var sig = rsa.SignHash(hash, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        Assert.True(rsa.VerifyHash(hash, sig, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void TokenManager_DetectsInsertAndRemoveEvents()
    {
        var backend = new MockTokenBackend();
        using var mgr = new TokenManager(backend);
        var events = new List<TokenEventDto>();
        mgr.TokenEvent += events.Add;
        Assert.Null(mgr.Rescan(false)); // nothing changes: no event
        using var a = MockToken.Create("A", "S-A");
        backend.Insert(a);
        var ins = mgr.Rescan(false);
        Assert.Equal(TokenEventKind.TokenInserted, ins!.Kind);
        Assert.Equal(new[] { "S-A" }, ins.AddedSerials);
        backend.Remove("S-A");
        var rem = mgr.Rescan(true);
        Assert.Equal(TokenEventKind.TokenRemoved, rem!.Kind);
        Assert.Equal(1, backend.ReloadCount);
        Assert.Equal(2, events.Count);
        Assert.True(rem.State.Generation > ins.State.Generation);
    }

    [Fact]
    public void DigestInfo_EncodeDecodeRoundTrip()
    {
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var di = DigestInfo.Encode(HashAlgorithmName.SHA256, hash);
        Assert.True(DigestInfo.TryDecode(di, out var alg, out var decoded));
        Assert.Equal(HashAlgorithmName.SHA256, alg);
        Assert.Equal(hash, decoded);
        Assert.False(DigestInfo.TryDecode(new byte[36], out _, out _));
    }

    [Fact]
    public void VendorLocator_HonoursExplicitOverrides()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "eps2003csp11v2.dll");
        File.WriteAllBytes(tmp, new byte[] { 0 });
        try
        {
            var libs = VendorLibraryLocator.Discover(new[] { tmp, "C:/does/not/exist.dll" });
            var l = Assert.Single(libs, x => x.Path == Path.GetFullPath(tmp));
            Assert.Contains("ePass2003", l.Vendor);
        }
        finally { File.Delete(tmp); }
    }

    [Fact]
    public void Config_SavesAndLoads()
    {
        var path = Path.Combine(Path.GetTempPath(), "dscsync-cfg-" + Guid.NewGuid().ToString("N") + ".json");
        var cfg = new DscSync.Core.Config.AppConfig { Mode = DscSync.Core.Config.SyncMode.Remote, RemoteHost = "10.0.0.5", PairingPin = "1234" };
        cfg.Save(path);
        var loaded = DscSync.Core.Config.AppConfig.Load(path);
        Assert.Equal(DscSync.Core.Config.SyncMode.Remote, loaded.Mode);
        Assert.Equal("10.0.0.5", loaded.RemoteHost);
        Assert.Equal(8, loaded.EmSignerPorts.Count);
        Assert.Contains("\"Remote\"", File.ReadAllText(path));
        File.Delete(path);
    }
}
