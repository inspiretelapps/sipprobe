#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
project="$root/src/SipProbe.Mac/SipProbe.Mac.csproj"
executable="InspireTel.SIPProbe"
version="1.5.0"

dotnet run --project "$root/tests/SipProbe.SelfTest/SipProbe.SelfTest.csproj" -c Release

publish_rid() {
  local rid="$1"
  local out="$root/dist/publish-$rid"
  rm -rf "$out"
  dotnet publish "$project" \
    -c Release \
    -r "$rid" \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:EnableCompressionInSingleFile=true \
    -p:DebugType=None \
    -p:DebugSymbols=false \
    -p:UseAppHost=true \
    -o "$out"
  chmod +x "$out/$executable"
}

package() {
  local rid="$1"
  local arch="${rid#linux-}"
  local out="$root/dist/publish-$rid"
  local stage="$root/dist/linux-$arch/InspireTel-SIPProbe"
  local tarball="$root/dist/InspireTel-SIPProbe-Linux-$arch.tar.gz"

  rm -rf "$(dirname "$stage")"
  mkdir -p "$stage"
  cp "$out/$executable" "$stage/"

  cat > "$stage/README.txt" <<'NOTE'
InspireTel SIP Probe (Linux)

Run:
  ./InspireTel.SIPProbe

Headless / CLI mode (no desktop required):
  ./InspireTel.SIPProbe --cli --cfg /path/to/phone.cfg

The build is self-contained, so no .NET install is needed. The graphical
mode still needs the usual desktop X11/Wayland libraries, which are present
on any normal desktop install. On a minimal server image install:

  Debian/Ubuntu: sudo apt install libx11-6 libice6 libsm6 libfontconfig1
  Fedora/RHEL:   sudo dnf install libX11 libICE libSM fontconfig

Listening for a handset ("Listen For Handset") binds UDP and TCP port 5060.
Ports below 1024 are privileged on Linux, but 5060 is not, so this does not
need root. Make sure no other softphone or PBX service already holds it.
NOTE

  rm -f "$tarball"
  tar -czf "$tarball" -C "$(dirname "$stage")" "$(basename "$stage")"
  echo "Built:  $stage/$executable (v$version)"
  echo "Packed: $tarball"
}

publish_rid linux-x64
package linux-x64

if [[ "${SIPPROBE_LINUX_ARM64:-0}" == "1" ]]; then
  publish_rid linux-arm64
  package linux-arm64
fi
