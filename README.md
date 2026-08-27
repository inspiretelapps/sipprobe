# InspireTel SIP Probe

A portable diagnostic that tests SIP registration independently of an IP handset. Use it on the customer LAN (or any path that should reach the PBX) to separate **network / credentials / PBX policy** from **phone configuration**.

Windows, macOS and Linux builds share the same engine. Packaged apps are attached to [GitHub Releases](https://github.com/inspiretelapps/sipprobe/releases) rather than committed here. Source: [inspiretelapps/sipprobe](https://github.com/inspiretelapps/sipprobe).

The program does not capture audio, install a driver, require administrator rights, or contact any telemetry service. It sends traffic only to the PBX hostname you enter (plus, if you use **Check PBX Status**, the Yeastar OpenAPI URL). SIP and API passwords are held in memory for the life of the process and are **never** written to the live trace or an exported log.

Current app version: **1.5**.

## What it proves

- DNS resolution of the PBX hostname
- UDP, TCP, and TLS reachability on **configurable** ports (defaults 5060 / 5060 / 5061; a custom destination port is included if it is not already in that set)
- TLS 1.2 negotiation, certificate hostname / trust / SAN, issuer, and validity versus the **local clock**
- Public NTP versus private NTP (for example `172.19.x.x`) loaded from a Yealink `.cfg`
- SIP ALG detection from Via sent-by / branch rewrite (`received` / `rport` alone is treated as normal NAT)
- A **diagnosis** after Test Path: whether the router is interfering, and what to do when you cannot log into it
- Receipt of a normal SIP `401` / `407` Digest challenge
- Authenticated SIP `REGISTER` using separate SIP user and authentication-name fields
- Holding that registration open so Yeastar can show the extension as registered (TLS/TCP drop as soon as the socket closes)
- Yealink outbound-proxy misconfig: proxy enabled with an empty address
- Yeastar OpenAPI check of extension online status, assigned phone, transport, and blocked IPs when the API exposes them
- The final PBX response code and a plain-language interpretation

**Test Path** does not send a password, so it will not lock the extension. Do not hammer **Test SIP Registration** after `403`, `429`, or repeated `401`.

## Install

Copy the app onto the laptop that should be able to reach the PBX:

| Platform | File | Notes |
|---|---|---|
| Windows x64 | `InspireTel.SIPProbe.exe` | Self-contained. No .NET install required. |
| macOS Apple Silicon | `InspireTel SIP Probe.app` | Self-contained, ad-hoc signed. |
| Linux x64 | `InspireTel.SIPProbe` | Self-contained. Needs the usual desktop X11 libraries for the GUI; `--cli` runs headless. |

Builds are **unsigned internal diagnostics**. Windows SmartScreen / application control and macOS Gatekeeper may block them. Follow the client's IT policy.

On macOS, if Gatekeeper refuses to open the app:

1. Right-click the app → **Open**, or
2. `xattr -dr com.apple.quarantine "InspireTel SIP Probe.app"`

The Mac app can also be copied into `/Applications`.

## Fastest workflow

1. Run the app on the affected network.
2. Click **Load Phone Config** and choose the generated Yealink `.cfg` (the same file provisioned to the handset).
3. Confirm the populated values: PBX hostname, SIP user, registration / authentication name, transport (usually TLS), destination port (usually 5061), expiry (often 600).
4. Hover the **i** next to a field if you are unsure what it is.
5. Click **Test Path**. This tries UDP, TCP, and TLS **without** the password. A `401` / `407` on a transport means that path works.
6. Leave **Keep Registered On The PBX** ticked (the default).
7. Click **Test SIP Registration**. A `200 OK` means credentials, transport, and the network path work from this computer.
8. While the banner reads **Passed — Registered**, confirm the extension in the Yeastar UI. Then click **Unregister Now** (or close the app).
9. Optional: open **Advanced**, enter OpenAPI Client ID and Secret (**Settings → Integrations → API** on the PBX), and click **Check PBX Status**.
10. Click **Export** and keep the redacted `.txt` report.

The password from a Yealink config stays only in the password field. It is never shown in the live trace or the export.

## The window

Both platforms use the same layout.

**Left — endpoint**

- PBX hostname, transport, port, SIP user, auth name, password
- Password **eye** icon shows / hides the value in the field only (still never logged)
- **Advanced** (collapsed by default): local port, expiry, timeout, TLS options, UDP/TCP/TLS ports used by Test Path, Yeastar OpenAPI URL / Client ID / Secret

**Left — actions** (title case, two columns)

| Action | What it does |
|---|---|
| **Load Phone Config** | Reads `account.1` (and NTP / outbound proxy) from a Yealink `.cfg` into the fields. Shows a green check once a file is loaded. |
| **Test Path** | Unauthenticated REGISTER on UDP, TCP, and TLS. A `401` is success. Safe first step. |
| **Test SIP Registration** | One authenticated REGISTER with the values in the form. |
| **Check PBX Status** | Yeastar OpenAPI lookup — not a SIP REGISTER. Needs Client ID and Secret under Advanced. |
| **Keep Registered On The PBX** | Default on. After a successful REGISTER, the probe keeps the SIP connection open. |
| **Unregister Now** | Sends `Expires: 0` on the **same** connection, then closes it. Replaces **Stop** once a session is held. |
| **Stop** | Cancels the test that is currently running. |

**Right — results**

- Chips: Config, Path, SIP Registration
- Banner: Config Loaded / Path Reachable / Passed — Registered / failures
- **Live trace**: colour log, no word wrap, horizontal scroll when a line is long
- **Clear** / **Export** (passwords and digest hashes redacted)

Hover any action or field **i** for a short explanation. **How to read results** in the status bar opens the same interpretation text.

macOS follows system light / dark and has a Dark switch in the header. Windows has the same Dark switch (it starts from the Windows app theme when that can be read).

## Why Keep Registered exists

Yeastar P-Series (Cloud) treats a TLS or TCP registration as gone as soon as the TCP connection closes. A probe that REGISTERs, gets `200 OK`, and then hangs up will look registered in the app and **unregistered on the PBX**.

With **Keep Registered On The PBX** ticked:

1. The probe keeps the SIP channel open.
2. It answers PBX OPTIONS / NOTIFY / PING / INFO with `200` and sends OPTIONS about every 15 seconds.
3. The banner reads **Passed — Registered**. Confirm the extension in Yeastar now.
4. **Unregister Now** removes the binding on that same socket (same Contact / local port). Closing the app also drops the hold.

Untick the box if you only want a one-shot proof of login. The probe then sends `Expires: 0` immediately after the `200`, as older versions did.

Do not leave a held session running as a substitute for the handset. It is a diagnostic binding only.

## Check PBX Status versus Test SIP Registration

| | Test SIP Registration | Check PBX Status |
|---|---|---|
| Protocol | SIP REGISTER | Yeastar OpenAPI HTTPS |
| Proves | This computer can authenticate as the extension | What the PBX database currently thinks |
| Credentials | SIP user / auth name / SIP password | OpenAPI Client ID and Secret |
| Typical use | After Test Path succeeds | Blocked IP, assigned phone, “is it online?” |

If SIP registration succeeds here but the handset stays on Registering, the path and credentials are not the problem. Look at the phone: NTP, outbound proxy, transport, or its own TLS trust.

## Yealink `.cfg` findings

**Load Phone Config** fills the form from `account.1` and also reports:

- NTP servers from `local_time.ntp*` — private `172.19.x.x` (Yeastar LAN NTP) will not work on a remote handset; TLS then fails because the clock is wrong.
- **Outbound proxy enabled with an empty address** — a Yealink can stay on Registering even when this probe REGISTERs successfully to the SIP hostname. Turn outbound proxy off on the phone / template, or set a real proxy host.

`%NULL%` placeholders in the cfg are ignored.

## Interpreting results

| Result | Meaning |
|---|---|
| DNS failure | Wrong hostname or DNS filtering / policy on the client network |
| TCP/TLS connect failure | Firewall / router / ISP policy, wrong destination port, or PBX listener unavailable |
| TLS handshake failure | TLS inspection, certificate trust / hostname / time issue, or incompatible TLS policy |
| SIP `401` or `407` on Test Path | Positive reachability: request and return traffic both work |
| SIP `200 OK` on Test SIP Registration | PBX, credentials, network path, and selected transport work from this laptop |
| App says registered, Yeastar does not | The SIP socket closed. Tick **Keep Registered On The PBX** and test again |
| Repeated `401` | Authentication name or password rejected |
| SIP `403` | Transport / security restriction, blocked IP, or registration forbidden |
| Via sent-by rewritten | SIP ALG rewrote the REGISTER; `received` / `rport` alone is normal NAT |
| UDP silent, TCP and/or TLS `401` | **The router** (SIP ALG or a UDP SIP filter), not the PBX. If you cannot change the router, put the Yealink on TLS (port 5061) and public NTP. Do not enable STUN to “fix” ALG |
| All transports fail | Not a specific ALG signature. Confirm hostname, then try a phone hotspot. Last resort: VPN / Yeastar remote access / cellular |
| Clock outside certificate dates / private NTP | Handset TLS will fail until NTP is a public server |
| Connection succeeds but no SIP response | SIP-aware filtering / ALG, proxy interference, or SIP service problem |
| Empty outbound proxy warning | Phone-side: proxy flag on, address blank — not a PBX reachability failure |

After **Test Path**, the banner states the diagnosis in plain language and lists **Do now** steps that do not need router access. Optional router steps (disable SIP ALG) sit underneath. The form switches to the working transport so **Test SIP Registration** uses that path.

## TLS certificate diagnostic option

Keep **Ignore certificate errors** unchecked for the real test (under **Advanced**). If the normal run fails at certificate validation, a second diagnostic-only run with the option checked can distinguish a trust-store problem from a blocked TLS connection.

A success obtained while ignoring certificate errors does **not** mean that the Yealink will trust the certificate. Fix the handset clock or certificate chain instead of leaving validation bypassed.

## Linux

Unpack the tarball and run the binary:

```bash
tar -xzf InspireTel-SIPProbe-Linux-x64.tar.gz
cd InspireTel-SIPProbe
./InspireTel.SIPProbe
```

The build is self-contained, so no .NET install is needed. The graphical mode still needs the desktop X11 libraries, which are present on any normal desktop install. On a minimal server image:

```bash
# Debian / Ubuntu
sudo apt install libx11-6 libice6 libsm6 libfontconfig1

# Fedora / RHEL
sudo dnf install libX11 libICE libSM fontconfig
```

On a headless box, skip the GUI entirely and use `--cli` (see below).

**Listen For Handset** binds UDP and TCP 5060. That is above the privileged range, so it does not need root — but make sure no other softphone or PBX service already holds the port.

## macOS and Linux command line

The Mac and Linux binaries can run the same engine without the GUI:

```bash
"/Applications/InspireTel SIP Probe.app/Contents/MacOS/InspireTel.SIPProbe" --cli --cfg "/path/to/phone.cfg"
```

`--cli --cfg <file>` runs Test Path and then Test SIP Registration. Add `--matrix` or `--register` to run only one of those. The CLI does **not** hold the session open (there is no operator to confirm it on the PBX). Passwords are still never printed.

You can also launch the GUI with a cfg already loaded:

```bash
open -a "InspireTel SIP Probe" --args --cfg "/path/to/phone.cfg"
```

## Building from source

Requirements: .NET 10 SDK on Windows, macOS, or Linux. Windows targeting packs are needed to compile the WinForms app from a non-Windows host.

```powershell
./build-windows.ps1
```

```bash
./build-macos.sh
./build-linux.sh
```

`build-macos.sh` produces `dist/InspireTel-SIPProbe-macOS-arm64.zip`. Set `SIPPROBE_MAC_INTEL=1` to also build the Intel (`osx-x64`) zip.

`build-linux.sh` produces `dist/InspireTel-SIPProbe-Linux-x64.tar.gz`. Set `SIPPROBE_LINUX_ARM64=1` to also build the `linux-arm64` tarball. It cross-publishes fine from macOS or Windows.

macOS and Linux share the one Avalonia project in `src/SipProbe.Mac`, so a change to the interface lands on both. `dist/` is gitignored.

Automated tests:

```bash
dotnet run --project tests/SipProbe.SelfTest/SipProbe.SelfTest.csproj -c Release
```

The self-tests cover SIP response parsing, RFC Digest calculation, configurable matrix ports, SIP ALG Via rewrite detection, router-diagnosis advice (UDP blocked / ALG / no router access), clock / NTP checks, Yealink `.cfg` parsing, Yeastar OpenAPI status / blocked-IP handling, and complete UDP, TCP, and TLS REGISTER / authentication / cleanup exchanges against local mock servers.

## Operational notes

- Unsigned internal builds: expect SmartScreen / Gatekeeper prompts.
- Never log or export SIP or API passwords. The live trace and export replace them with `REDACTED`.
- Test Path is no-auth on purpose so a failed password cannot lock the extension.
- After `403`, `429`, or repeated `401`, stop. Check **Blocked IPs** on the PBX (or **Check PBX Status**) before trying again.
- A held registration is removed by **Unregister Now** or by closing the app. If cleanup cannot complete, the binding expires according to the configured registration timer.
- Do not treat a successful probe as proof that the handset is correctly provisioned. It only proves this computer, with these values, on this network.
