# InspireTel SIP Probe

A portable diagnostic utility that tests SIP registration independently of an IP handset. Builds exist for **Windows** and **macOS**.

Private source: [inspiretelapps/sipprobe](https://github.com/inspiretelapps/sipprobe).
Packaged apps are attached to [GitHub Releases](https://github.com/inspiretelapps/sipprobe/releases) rather than committed here.

## What it proves

- DNS resolution of the PBX hostname
- UDP, TCP, or TLS reachability to the SIP service on **configurable** ports (defaults 5060/5060/5061; a custom destination port is included if it is not already in that set)
- TLS 1.2 negotiation, certificate hostname/trust/SAN, certificate issuer, and validity dates versus the **local clock**
- Public NTP vs private NTP (for example `172.19.x.x`) loaded from a Yealink `.cfg`
- SIP ALG detection from Via sent-by / branch rewrite (`received`/`rport` alone is treated as normal NAT)
- Receipt of a normal SIP `401`/`407` Digest challenge
- Authenticated SIP `REGISTER` using separate SIP user and authentication-name fields
- Yeastar OpenAPI check of extension online status, assigned phone, transport, and blocked IPs when the API exposes them
- The final PBX response code and a plain-language interpretation
- Automatic removal of a successful temporary registration using `Expires: 0`

The program does not capture audio, install a driver, require administrator rights, or contact any telemetry service. It sends traffic only to the PBX hostname entered by the operator.

## Fastest workflow for the current extension

1. Copy the app to the affected laptop:
   - Windows: `InspireTel.SIPProbe.exe`
   - macOS: `InspireTel SIP Probe.app` (Apple Silicon zip)
2. Run it. It is self-contained and needs no .NET installation. On macOS, if Gatekeeper blocks it, right-click the app and choose **Open**, or run `xattr -dr com.apple.quarantine "InspireTel SIP Probe.app"`.
3. Click **Load Yealink .cfg** and choose the generated configuration uploaded to the T40G.
4. Confirm that the populated values show:
   - the intended PBX hostname;
   - SIP user `101`;
   - the generated registration/authentication name;
   - transport `TLS`;
   - destination port `5061`;
   - expiry `600`.
5. Confirm the **Matrix** tab ports (change them if this PBX uses nonstandard SIP ports).
6. Click **Run transport matrix (no auth)** first.
7. Then select **TLS / 5061** and click **Run authenticated REGISTER**.
8. Optional: on the **PBX API** tab enter OpenAPI Client ID/Secret and click **Check PBX status**.
9. Click **Export log** and retain the redacted `.txt` report.

The password loaded from a Yealink configuration remains only in the password field for the life of the process. It is never written to the screen log or exported report.

## Interpreting results

| Result | Meaning |
|---|---|
| DNS failure | Wrong hostname or DNS filtering/policy on the client network |
| TCP/TLS connect failure | Firewall/router/ISP policy, wrong destination port, or PBX listener unavailable |
| TLS handshake failure | TLS inspection, certificate trust/hostname/time issue, or incompatible TLS policy |
| SIP `401` or `407` | Positive reachability result: request and return traffic both work |
| SIP `200 OK` | PBX, credentials, network path, and selected transport work from the laptop; focus on the handset |
| Repeated `401` | Authentication name or password rejected |
| SIP `403` | Transport/security restriction, blocked IP, or registration forbidden |
| Via sent-by rewritten | SIP ALG rewrote the REGISTER; `received`/`rport` alone is normal NAT |
| Clock outside certificate dates / private NTP | Handset TLS will fail until NTP is a public server |
| Connection succeeds but no SIP response | SIP-aware filtering/ALG, proxy interference, or SIP service problem |

The matrix deliberately stops after the normal unauthenticated challenge. It does not send three bad passwords and therefore avoids creating unnecessary PBX lockouts.

## TLS certificate diagnostic option

Keep **Ignore certificate errors** unchecked for the real test. If the normal run fails at certificate validation, a second diagnostic-only run with the option checked can distinguish a trust-store problem from a blocked TLS connection.

A success obtained while ignoring certificate errors does **not** mean that the Yealink will trust the certificate. Fix the handset clock or certificate chain instead of leaving validation bypassed.

## Building from source

Requirements: .NET 10 SDK on Windows, macOS, or Linux.

```powershell
./build-windows.ps1
```

```bash
./build-macos.sh
```

`build-macos.sh` produces `dist/InspireTel-SIPProbe-macOS-arm64.zip`. Set `SIPPROBE_MAC_INTEL=1` to also build the Intel (`osx-x64`) zip.

Automated tests:

```powershell
dotnet run --project tests/SipProbe.SelfTest/SipProbe.SelfTest.csproj -c Release
```

The self-tests cover SIP response parsing, RFC Digest calculation, configurable matrix ports, SIP ALG Via rewrite detection, clock/NTP checks, Yealink `.cfg` parsing, Yeastar OpenAPI status/blocked-IP handling, and complete UDP, TCP, and TLS REGISTER/authentication/cleanup exchanges against local mock servers.

## Operational notes

- The builds are unsigned internal diagnostic binaries. Windows application-control policy and macOS Gatekeeper may prevent them from running; follow the client's normal IT policy.
- Do not test repeatedly after `403`, `429`, or repeated `401` responses. Check PBX **Blocked IPs** first.
- A successful authenticated probe briefly creates a registration and then automatically removes it. If cleanup cannot complete, the binding expires according to the configured registration timer.
