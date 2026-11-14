using System.Security.Cryptography;
using System.Text;
using DscSync.Core.Protocol;

namespace DscSync.Core.Security;

public sealed class HandshakeResult
{
    public required string PeerRole { get; init; }
    public required string PeerMachine { get; init; }
}

public sealed class PairingFailedException : Exception
{
    public PairingFailedException(string message) : base(message) { }
}

/// <summary>
/// Mutual authentication with a shared pairing PIN. Neither side ever sends the PIN; each proves knowledge of
/// PBKDF2(PIN) by MACing both nonces plus a channel binding (SHA-256 of the TLS server certificate for the TCP
/// tunnel, a fixed label for the RDP DVC). A MITM terminating TLS changes the binding and fails the proof.
/// </summary>
public static class PairingHandshake
{
    public const string RoleLocal = "local";
    public const string RoleRemote = "remote";
    private const int Iterations = 120_000;

    public static async Task<HandshakeResult> RunAsync(FrameCodec codec, string role, string pin, byte[] channelBinding, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(pin)) throw new PairingFailedException("Pairing PIN is not configured");
        var myNonce = RandomNumberGenerator.GetBytes(32);
        // The remote (host) side chooses the salt; the local side adopts it.
        var mySalt = role == RoleRemote ? RandomNumberGenerator.GetBytes(16) : Array.Empty<byte>();
        var hello = new HelloDto
        {
            Version = DscConstants.ProtocolVersion,
            Role = role,
            Machine = Environment.MachineName,
            Nonce = myNonce,
            Salt = mySalt,
        };
        await codec.WriteAsync(FrameType.Hello, 0, ProtocolJson.Serialize(hello, ProtocolJson.Default.HelloDto), ct).ConfigureAwait(false);

        var frame = await codec.ReadAsync(ct).ConfigureAwait(false) ?? throw new PairingFailedException("Peer closed during handshake");
        if (frame.Type != FrameType.Hello) throw new PairingFailedException($"Expected Hello, got {frame.Type}");
        var peer = ProtocolJson.Deserialize(frame.Payload, ProtocolJson.Default.HelloDto);
        if (peer.Version != DscConstants.ProtocolVersion) throw new PairingFailedException($"Protocol version mismatch (peer {peer.Version}, ours {DscConstants.ProtocolVersion})");
        if (peer.Role == role) throw new PairingFailedException($"Both sides are configured as '{role}'. Set one PC to Local and the other to Remote mode.");
        if (peer.Nonce.Length != 32) throw new PairingFailedException("Invalid peer nonce");

        var salt = role == RoleRemote ? mySalt : peer.Salt;
        if (salt.Length < 16) throw new PairingFailedException("Invalid pairing salt");
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(pin.Trim()), salt, Iterations, HashAlgorithmName.SHA256, 32);

        var myMac = ComputeMac(key, role, myNonce, peer.Nonce, channelBinding);
        await codec.WriteAsync(FrameType.Proof, 0, ProtocolJson.Serialize(new ProofDto { Mac = myMac }, ProtocolJson.Default.ProofDto), ct).ConfigureAwait(false);

        var proofFrame = await codec.ReadAsync(ct).ConfigureAwait(false) ?? throw new PairingFailedException("Peer closed during handshake (wrong PIN?)");
        if (proofFrame.Type != FrameType.Proof) throw new PairingFailedException($"Expected Proof, got {proofFrame.Type}");
        var proof = ProtocolJson.Deserialize(proofFrame.Payload, ProtocolJson.Default.ProofDto);
        var expected = ComputeMac(key, peer.Role, peer.Nonce, myNonce, channelBinding);
        if (!CryptographicOperations.FixedTimeEquals(expected, proof.Mac))
            throw new PairingFailedException("Pairing PIN mismatch or tunnel tampered (channel binding differs)");

        return new HandshakeResult { PeerRole = peer.Role, PeerMachine = peer.Machine };
    }

    private static byte[] ComputeMac(byte[] key, string role, byte[] senderNonce, byte[] receiverNonce, byte[] binding)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        h.AppendData(Encoding.ASCII.GetBytes("DSC-Sync-v1|" + role + "|"));
        h.AppendData(senderNonce);
        h.AppendData(receiverNonce);
        h.AppendData(binding);
        return h.GetHashAndReset();
    }

    public static byte[] DvcChannelBinding => Encoding.ASCII.GetBytes("rdp-dvc:" + DscConstants.DvcChannelName);

    public static byte[] TlsChannelBinding(byte[] serverCertificateDer) => SHA256.HashData(serverCertificateDer);
}
