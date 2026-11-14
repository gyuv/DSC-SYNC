# DSC-Sync — Implementation Plan

Target platforms: **Local PC = Windows 10/11 (token source)**, **Remote = Windows Server 2019 Standard (RDP target)**.
Server 2019 SChannel has no TLS 1.3, so the fallback tunnel negotiates TLS 1.3 when available and TLS 1.2 otherwise,
always bound to the pairing PIN (HMAC proof over the server certificate hash), so a MITM cannot downgrade or relay.

## Phase 1 — Core protocol & PKCS#11 model (`DSC-Sync.Core`)
- [x] Binary frame codec (length-prefixed, typed, stream-id multiplexed) with AOT-safe JSON (source-generated) payloads
- [x] `MuxConnection`: RPC request/response, events, multiplexed byte streams (`MuxStream`), ping/keep-alive
- [x] PIN pairing handshake (PBKDF2 + HMAC-SHA256 proofs + channel binding)
- [x] DTOs: token state, certificate metadata (CN, O, serial, issuer CA, validity), sign requests, RPC methods
- [x] PKCS#11 constants + `VirtualP11Core` (slots/sessions/objects/sign state machine) + P11 named-pipe protocol
- [x] Config model (`%AppData%\DSC-Sync\config.json`)
- [x] Tests: framing, mux RPC, handshake success/failure

## Phase 2 — Transports & port proxy (`DSC-Sync.Tunnel`, `DSC-Sync.RdpPlugin`)
- [x] TLS tunnel server/client (default port 49155, self-signed persisted cert, TLS1.3→1.2)
- [x] RDP DVC server transport (`WTSVirtualChannelOpenEx` + `CHANNEL_OPTION_DYNAMIC`, PDU header stripping)
- [x] RDP client plug-in (`IWTSPlugin` COM, mstsc add-in) bridging the DVC to the local app via named pipe
- [x] Loopback emSigner port proxy (raw TCP over mux streams: TLS/SNI/WebSocket preserved end-to-end) with hot reset
- [x] emSigner localhost certificate probe (captures the cert presented on 127.0.0.1:port)
- [x] Tests: proxied HTTP + WebSocket-style bidirectional traffic over mux, TLS tunnel + PIN

## Phase 3 — PKCS#11 bridge (`DSC-Sync.Pkcs11Bridge`, `DSC-Sync.P11`)
- [x] Vendor library locator (ePass2003, ProxKey/Watchdata, TrustKey, SafeSign, mToken, …)
- [x] `Pkcs11TokenBackend` (Pkcs11Interop) with clean unload/reload on hot-swap
- [x] `MockTokenBackend` (simulated token with CA-issued RSA cert, insert/remove)
- [x] `TokenManager` (rescan, generation counter, TOKEN_INSERTED / TOKEN_REMOVED diffing)
- [x] `LocalAgent` & `RemoteHost` engines (session loop, RPC handler, event push, proxy reset, cert sync)
- [x] `RemoteRsa` (System.Security.Cryptography RSA whose private op runs on the remote token)
- [x] `DSC-Sync-P11.dll` NativeAOT unmanaged exports (`C_GetFunctionList` + full CK_FUNCTION_LIST)
- [x] Tests: hot-swap < 1s, SHA-256 / PSS roundtrip through virtual P11 → tunnel → mock token

## Phase 4 — WPF tray app (`DSC-Sync.App`)
- [x] Dark glass theme (#0F172A / #3B82F6 / #F59E0B), tray NotifyIcon, mode switcher, live token card
- [x] Port & service health monitor (8 emSigner ports, emSigner, SSL trust, SCardSvr, transport)
- [x] Windows: device notifications (USB + smart-card reader GUIDs), emSigner stopper, Root store trust manager
- [x] One-click diagnostics & auto-fix
- [x] Windows Service mode (`--service`) + `sc create` installer helper, RDP plug-in registration helper

## Phase 5 — PDF signing, packaging, docs
- [x] Quick PDF signer (iText7 external CMS container signed by remote token), drag-drop, page/rect
- [x] PDF sign test (verifies CMS signature) without hardware
- [x] `build-release.ps1` → `dist/Local`, `dist/Remote`, install guides
- [x] README with architecture, install & troubleshooting

## Phase 6 — Multi-user server & reporting (added after requirements update)
- [x] Per-session pipes (P11, DVC plug-in) keyed by RDS session id
- [x] Machine-wide emSigner port router with election / fail-over, routing by browser socket owner session
- [x] Native (NativeAOT) mstsc plug-in — no .NET runtime or COM registration on user PCs
- [x] Audit log (who / when / which DSC / which app or portal / result), Reports tab, CSV export
- [x] Zero-config RDP mode (PIN optional over RDP, required for TCP), per-user TLS port auto-selection
- [x] Setup scripts (per-user, all-users server), support bundle export, rolling logs
- [x] GitHub Actions Windows build → downloadable Local / Remote packages

## Verification notes
- `dotnet build` + `dotnet test` (34 tests) pass on Linux; NativeAOT publish of DSC-Sync-P11 verified (no AOT warnings).
- The WPF app cannot be compiled by the Linux SDK; all of its C# (services + code-behind) was compile-checked against
  the WindowsDesktop reference pack, and the full Windows build/test/package runs in `.github/workflows/build.yml`.
