using System.Text;
using DscSync.Core.Protocol;
using DscSync.Core.Security;
using Xunit;

namespace DscSync.Tests;

public class ProtocolTests
{
    [Fact]
    public async Task FrameCodec_RoundTripsFrames()
    {
        var ms = new MemoryStream();
        var writer = new FrameCodec(ms);
        await writer.WriteAsync(FrameType.StreamData, 42, Encoding.UTF8.GetBytes("hello"));
        await writer.WriteAsync(FrameType.Ping, 0, Array.Empty<byte>());
        ms.Position = 0;
        var reader = new FrameCodec(ms);
        var f1 = await reader.ReadAsync();
        var f2 = await reader.ReadAsync();
        var f3 = await reader.ReadAsync();
        Assert.Equal(FrameType.StreamData, f1!.Value.Type);
        Assert.Equal(42u, f1.Value.StreamId);
        Assert.Equal("hello", Encoding.UTF8.GetString(f1.Value.Payload));
        Assert.Equal(FrameType.Ping, f2!.Value.Type);
        Assert.Null(f3);
    }

    [Fact]
    public async Task FrameCodec_RejectsOversizedLength()
    {
        var ms = new MemoryStream(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0 });
        await Assert.ThrowsAsync<InvalidDataException>(() => new FrameCodec(ms).ReadAsync());
    }

    [Fact]
    public async Task Handshake_SucceedsWithSamePin()
    {
        var (a, b) = await TestUtil.CreateDuplexAsync();
        var binding = new byte[] { 1, 2, 3 };
        var t1 = PairingHandshake.RunAsync(new FrameCodec(a), PairingHandshake.RoleRemote, "1234", binding, CancellationToken.None);
        var t2 = PairingHandshake.RunAsync(new FrameCodec(b), PairingHandshake.RoleLocal, "1234", binding, CancellationToken.None);
        var results = await Task.WhenAll(t1, t2);
        Assert.Equal(PairingHandshake.RoleLocal, results[0].PeerRole);
        Assert.Equal(PairingHandshake.RoleRemote, results[1].PeerRole);
    }

    [Fact]
    public async Task Handshake_FailsWithWrongPin()
    {
        var (a, b) = await TestUtil.CreateDuplexAsync();
        var t1 = PairingHandshake.RunAsync(new FrameCodec(a), PairingHandshake.RoleRemote, "1234", Array.Empty<byte>(), CancellationToken.None);
        var t2 = PairingHandshake.RunAsync(new FrameCodec(b), PairingHandshake.RoleLocal, "9999", Array.Empty<byte>(), CancellationToken.None);
        await Assert.ThrowsAsync<PairingFailedException>(() => t1);
        await Assert.ThrowsAsync<PairingFailedException>(() => t2);
    }

    [Fact]
    public async Task Handshake_FailsWhenChannelBindingDiffers()
    {
        // Simulates a TLS man-in-the-middle presenting a different certificate to each side.
        var (a, b) = await TestUtil.CreateDuplexAsync();
        var t1 = PairingHandshake.RunAsync(new FrameCodec(a), PairingHandshake.RoleRemote, "1234", new byte[] { 1 }, CancellationToken.None);
        var t2 = PairingHandshake.RunAsync(new FrameCodec(b), PairingHandshake.RoleLocal, "1234", new byte[] { 2 }, CancellationToken.None);
        await Assert.ThrowsAsync<PairingFailedException>(() => t1);
        await Assert.ThrowsAsync<PairingFailedException>(() => t2);
    }

    [Fact]
    public async Task Handshake_RejectsSameRoleOnBothSides()
    {
        var (a, b) = await TestUtil.CreateDuplexAsync();
        var t1 = PairingHandshake.RunAsync(new FrameCodec(a), PairingHandshake.RoleLocal, "1234", Array.Empty<byte>(), CancellationToken.None);
        var t2 = PairingHandshake.RunAsync(new FrameCodec(b), PairingHandshake.RoleLocal, "1234", Array.Empty<byte>(), CancellationToken.None);
        var ex = await Assert.ThrowsAsync<PairingFailedException>(() => t1);
        Assert.Contains("Local", ex.Message, StringComparison.OrdinalIgnoreCase);
        await Assert.ThrowsAsync<PairingFailedException>(() => t2);
    }

    [Fact]
    public async Task Mux_RpcEventsAndErrors()
    {
        var gotEvent = new TaskCompletionSource<string>();
        var (host, client) = await TestUtil.CreateMuxPairAsync(
            configureClient: c => c.RpcHandler = (m, body, _) => m switch
            {
                "Echo" => Task.FromResult<byte[]?>(body),
                _ => throw new RpcException(0xA0, "bad pin"),
            },
            configureHost: h => h.EventReceived += (name, body) => gotEvent.TrySetResult(name + ":" + Encoding.UTF8.GetString(body!)));

        var reply = await host.CallAsync("Echo", Encoding.UTF8.GetBytes("ping"));
        Assert.Equal("ping", Encoding.UTF8.GetString(reply!));

        var ex = await Assert.ThrowsAsync<RpcException>(() => host.CallAsync("Other", null));
        Assert.Equal(0xA0UL, ex.Code);

        await client.SendEventAsync("TokenEvent", Encoding.UTF8.GetBytes("x"));
        Assert.Equal("TokenEvent:x", await gotEvent.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        // Many concurrent calls are correlated correctly.
        var calls = Enumerable.Range(0, 50).Select(async i =>
            Encoding.UTF8.GetString((await host.CallAsync("Echo", Encoding.UTF8.GetBytes(i.ToString())))!)).ToList();
        var results = await Task.WhenAll(calls);
        Assert.Equal(Enumerable.Range(0, 50).Select(i => i.ToString()), results);

        await host.DisposeAsync();
        await client.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(client.IsClosed);
    }

    [Fact]
    public async Task Mux_MultiplexesIndependentStreams()
    {
        var (host, client) = await TestUtil.CreateMuxPairAsync(configureClient: c => c.StreamOpenHandler = async (port, ct) =>
        {
            if (port == 9) return null;
            // Echo service that prefixes its port number.
            var (a, b) = await TestUtil.CreateDuplexAsync();
            _ = Task.Run(async () =>
            {
                var buf = new byte[1024];
                int n;
                while ((n = await b.ReadAsync(buf)) > 0)
                    await b.WriteAsync(Encoding.UTF8.GetBytes($"{port}:{Encoding.UTF8.GetString(buf, 0, n)}"));
                b.Dispose();
            });
            return a;
        });

        await Assert.ThrowsAsync<IOException>(() => host.OpenStreamAsync(9));

        var streams = await Task.WhenAll(Enumerable.Range(1, 8).Select(p => host.OpenStreamAsync(1000 + p)));
        Assert.Equal(8, host.ActiveStreamCount);
        await Task.WhenAll(streams.Select(async s =>
        {
            await s.WriteAsync(Encoding.UTF8.GetBytes("data"));
            var buf = new byte[64];
            int n = await s.ReadAsync(buf);
            Assert.Equal($"{s.Port}:data", Encoding.UTF8.GetString(buf, 0, n));
        }));

        host.CloseAllStreams();
        await TestUtil.WaitUntilAsync(() => host.ActiveStreamCount == 0 && client.ActiveStreamCount == 0, TimeSpan.FromSeconds(5));
        await host.DisposeAsync();
        await client.DisposeAsync();
    }

    [Fact]
    public async Task Mux_LargePayloadIsChunkedAndReassembled()
    {
        var (host, client) = await TestUtil.CreateMuxPairAsync(configureClient: c => c.StreamOpenHandler = async (port, ct) =>
        {
            var (a, b) = await TestUtil.CreateDuplexAsync();
            _ = Task.Run(async () => { await b.CopyToAsync(b); });
            return a;
        });
        var s = await host.OpenStreamAsync(1);
        var data = new byte[300_000];
        Random.Shared.NextBytes(data);
        var send = s.WriteAsync(data).AsTask();
        var received = new MemoryStream();
        var buf = new byte[8192];
        while (received.Length < data.Length)
        {
            int n = await s.ReadAsync(buf);
            Assert.True(n > 0);
            received.Write(buf, 0, n);
        }
        await send;
        Assert.Equal(data, received.ToArray());
        await host.DisposeAsync();
        await client.DisposeAsync();
    }
}
