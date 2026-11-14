# DSC-Sync — Implementation Plan

Target platforms: **Local PC = Windows 10/11 (token source)**, **Remote = Windows Server 2019 Standard (RDP target)**.
Server 2019 SChannel has no TLS 1.3, so the fallback tunnel negotiates TLS 1.3 when available and TLS 1.2 otherwise,
always bound to the pairing PIN (HMAC proof over the server certificate hash), so a MITM cannot downgrade or relay.

## Phase 1 — Core protocol & PKCS#11 model (`DSC-Sync.Core`)
- [ ] Binary frame codec (length-prefixed, typed, stream-id multiplexed) with AOT-safe JSON (source-generated) payloads
- [ ] `MuxConnection`: RPC request/response, events, multiplexed byte streams (`MuxStream`), ping/keep-alive
- [ ] PIN pairing handshake (PBKDF2 + HMAC-SHA256 proofs + channel binding)
- [ ] DTOs: token state, certificate metadata (CN, O, serial, issuer CA, validity), sign requests, RPC methods
- [ ] PKCS#11 constants + `VirtualP11Core` (slots/sessions/objects/sign state machine) + P11 named-pipe protocol
- [ ] Config model (`%AppData%\DSC-Sync\config.json`)
- [ ] Tests: framing, mux RPC, handshake success/failure

## Phase 2 — Transports & port proxy (`DSC-Sync.Tunnel`, `DSC-Sync.RdpPlugin`)
- [ ] TLS tunnel server/client (default port 49155, self-signed persisted cert, TLS1.3→1.2)
- [ ] RDP DVC server transport (`WTSVirtualChannelOpenEx` + `CHANNEL_OPTION_DYNAMIC`, PDU header stripping)
- [ ] RDP client plug-in (`IWTSPlugin` COM, mstsc add-in) bridging the DVC to the local app via named pipe
- [ ] Loopback emSigner port proxy (raw TCP over mux streams: TLS/SNI/WebSocket preserved end-to-end) with hot reset
- [ ] emSigner localhost certificate probe (captures the cert presented on 127.0.0.1:port)
- [ ] Tests: proxied HTTP + WebSocket-style bidirectional traffic over mux, TLS tunnel + PIN

## Phase 3 — PKCS#11 bridge (`DSC-Sync.Pkcs11Bridge`, `DSC-Sync.P11`)
- [ ] Vendor library locator (ePass2003, ProxKey/Watchdata, TrustKey, SafeSign, mToken, …)
- [ ] `Pkcs11TokenBackend` (Pkcs11Interop) with clean unload/reload on hot-swap
- [ ] `MockTokenBackend` (simulated token with CA-issued RSA cert, insert/remove)
- [ ] `TokenManager` (rescan, generation counter, TOKEN_INSERTED / TOKEN_REMOVED diffing)
- [ ] `LocalAgent` & `RemoteHost` engines (session loop, RPC handler, event push, proxy reset, cert sync)
- [ ] `RemoteRsa` (System.Security.Cryptography RSA whose private op runs on the remote token)
- [ ] `DSC-Sync-P11.dll` NativeAOT unmanaged exports (`C_GetFunctionList` + full CK_FUNCTION_LIST)
- [ ] Tests: hot-swap < 1s, SHA-256 / PSS roundtrip through virtual P11 → tunnel → mock token

## Phase 4 — WPF tray app (`DSC-Sync.App`)
- [ ] Dark glass theme (#0F172A / #3B82F6 / #F59E0B), tray NotifyIcon, mode switcher, live token card
- [ ] Port & service health monitor (8 emSigner ports, emSigner, SSL trust, SCardSvr, transport)
- [ ] Windows: device notifications (USB + smart-card reader GUIDs), emSigner stopper, Root store trust manager
- [ ] One-click diagnostics & auto-fix
- [ ] Windows Service mode (`--service`) + `sc create` installer helper, RDP plug-in registration helper

## Phase 5 — PDF signing, packaging, docs
- [ ] Quick PDF signer (iText7 external CMS container signed by remote token), drag-drop, page/rect
- [ ] PDF sign test (verifies CMS signature) without hardware
- [ ] `build-release.ps1` → `dist/Local`, `dist/Remote`, install guides
- [ ] README with architecture, install & troubleshooting
