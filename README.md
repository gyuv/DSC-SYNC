# DSC-Sync

Use a **USB Digital Signature Certificate (DSC) token plugged into your own PC** inside a **Remote Desktop /
cloud Windows server** — for **GST, MCA V3, Income Tax and TRACES (emSigner)** and for **PDF signing (Adobe
Acrobat or the built-in signer)**. Designed for **15+ people working on one Windows Server 2019** at the same
time, each with their own token on their own PC.

* **Free, nothing extra to install.** One self-contained `DSC-Sync.exe` (no .NET runtime, no drivers, no
  kernel components, no cloud relay or paid service). The token vendor's normal driver on the Local PC is all
  that's needed.
* **Zero configuration over RDP.** The Local PC and the server talk through the Remote Desktop connection
  itself (RDP Dynamic Virtual Channel): no open ports, no firewall rules, no VPN.
* **Automatic hot-swap.** Pull one token out, plug another in: the server sees it in < 1 s, stale portal
  connections are dropped and the next signature uses the new certificate.
* **Usage reports.** Who used which DSC, when, from which application/portal, with filters and Excel export.

## How it works

```
 LOCAL PC (Windows 10/11)                          SERVER (Windows Server 2019, many users)
 ┌───────────────────────────────┐   RDP DVC      ┌───────────────────────────────────────────────┐
 │ USB token ─ vendor PKCS#11    │  "DSCSYNC"     │ DSC-Sync (one per user session)               │
 │   │   (Pkcs11Interop)         │◄──────────────►│  ├─ DSC-Sync-P11.dll ◄── Acrobat / Java / …   │
 │ DSC-Sync (Local mode)         │  or TLS 1.2/1.3│  ├─ port router 127.0.0.1:1585,8080,2015,…    │
 │   ├─ hot-swap watcher         │  tunnel (PIN)  │  │     ▲ routes each browser connection to    │
 │   ├─ RPC: login/sign          │                │  │     │ the session that owns the browser   │
 │   └─ emSigner 127.0.0.1:1585… │                │  └─ audit log → Reports                       │
 │ mstsc + DSC-Sync-RdpPlugin.dll│                │ Chrome/Edge ── GST/MCA/IT portal (emSigner)   │
 └───────────────────────────────┘                └───────────────────────────────────────────────┘
```

**Channel A – portals (emSigner).** emSigner keeps running on the Local PC, where the token is. On the server,
DSC-Sync binds the emSigner loopback ports and relays raw bytes through the tunnel to `127.0.0.1:<same port>` on
the user's Local PC, so TLS (incl. SNI), keep-alive and WebSockets pass through untouched. On a multi-user
server those ports are shared by everyone, so one DSC-Sync instance owns them (automatic election + fail-over
when that user logs off) and routes each connection to the right user by looking up which RDS session owns the
browser socket (`GetExtendedTcpTable` → PID → session). emSigner's `127.0.0.1` certificate is fetched from the
Local PC and trusted on the server, so Chrome/Edge show no certificate errors.

**Channel B – PDF / PKCS#11.** `DSC-Sync-P11.dll` is a PKCS#11 v2.40 module (NativeAOT, no runtime) that
mirrors the Local token's slots, certificates and keys. Private-key operations (`CKM_RSA_PKCS`,
`CKM_SHA1/256/384/512_RSA_PKCS`, `CKM_RSA_PKCS_PSS`, `CKM_SHA*_RSA_PKCS_PSS`, single and multi-part) are
forwarded to the physical token. The built-in **Quick PDF Signer** signs with the same path (adbe.pkcs7.detached,
visible box placed by dragging on the page preview).

**Security.** Each side proves knowledge of the pairing PIN with HMAC-SHA256 over both nonces and a channel
binding (SHA-256 of the TLS certificate), so a man-in-the-middle cannot relay or downgrade the tunnel. Windows
Server 2019 has no TLS 1.3 in SChannel, so TLS 1.3 is used when available and TLS 1.2 otherwise. Over RDP, the
channel exists only inside the user's own encrypted RDP session; a PIN is optional there. The token PIN never
leaves memory and is never logged. Pipes are per-session (`CurrentUserOnly`); the router pipe only accepts the
DSC-Sync process.

## Install

Download the two zips from the GitHub Actions run (artifact **DSC-Sync-Local** / **DSC-Sync-Remote**) or build
them yourself (below). See `packaging/INSTALL-LOCAL.txt` and `packaging/INSTALL-REMOTE.txt`.

* **Server (admin, once):** `install-server-all-users.cmd` → starts DSC-Sync for every user at sign-in.
* **Each user's PC:** `install-local.cmd` (no admin) → then just connect with Remote Desktop.

## Build

Requires the .NET 8 SDK on Windows.

```powershell
powershell -ExecutionPolicy Bypass -File .\build-release.ps1
```

Produces `dist\DSC-Sync-Local\`, `dist\DSC-Sync-Remote\` and matching zips. The GitHub workflow
`.github/workflows/build.yml` runs the same script on `windows-latest` for every push.

```bash
dotnet test tests/DSC-Sync.Tests   # runs on Windows or Linux, no hardware needed
```

## Projects

| Project | Purpose |
|---|---|
| `DSC-Sync.Core` | Frame codec, multiplexer (RPC + events + streams), PIN pairing, DTOs, PKCS#11 constants, `VirtualP11Core`, pipes, config, audit log |
| `DSC-Sync.Tunnel` | RDP DVC server transport (`WTSVirtualChannelOpenEx`), TLS tunnel, loopback port proxy, multi-session port router, emSigner cert probe |
| `DSC-Sync.Pkcs11Bridge` | Vendor DLL discovery, Pkcs11Interop backend, simulated token, `TokenManager` (hot-swap), `LocalAgent` / `RemoteHost`, token-backed `RSA`, PDF signing |
| `DSC-Sync.P11` | `DSC-Sync-P11.dll` — NativeAOT PKCS#11 exports (`C_GetFunctionList` + 68-entry function list) |
| `DSC-Sync.RdpPlugin` | `DSC-Sync-RdpPlugin.dll` — NativeAOT mstsc DVC plug-in (`VirtualChannelGetInstance`) |
| `DSC-Sync.App` | WPF tray app: dashboard, health monitor & auto-fix, Quick PDF Signer, Reports, settings, service mode |
| `DSC-Sync.Tests` | 34 tests: protocol, pairing/MITM, multiplexing, TLS link, hot-swap timing, all mechanisms through the virtual PKCS#11 module, port proxy, multi-user routing & fail-over, audit, PDF signing |

## Known limits

* emSigner's PIN dialog is shown by emSigner on the **Local PC** screen (that's where emSigner runs).
* Adobe Acrobat needs the PKCS#11 module attached once (Preferences ▸ Signatures ▸ Identities ▸ PKCS#11
  Modules). Making the token appear in the Windows certificate store (CAPI/CNG) would need a signed
  Microsoft-certified provider and is intentionally not done.
* The 32-bit PKCS#11 module is built when the .NET SDK supports NativeAOT for win-x86; the 64-bit module is
  always built.
* The RDP channel needs the Microsoft Remote Desktop client (`mstsc`). For other remote tools use the TLS
  tunnel (Settings ▸ Transport).
