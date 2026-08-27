#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
project="$root/src/SipProbe.Mac/SipProbe.Mac.csproj"
app_name="InspireTel SIP Probe"
executable="InspireTel.SIPProbe"
version="1.5.0"

dotnet run --project "$root/tests/SipProbe.SelfTest/SipProbe.SelfTest.csproj" -c Release

publish_rid() {
  local rid="$1"
  local out="$root/dist/$rid"
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
}

make_app() {
  local rid="$1"
  local publish_dir="$root/dist/$rid"
  local app_dir="$root/dist/macos-${rid#osx-}/${app_name}.app"
  rm -rf "$app_dir"
  mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
  rsync -a --exclude Info.plist "$publish_dir"/ "$app_dir/Contents/MacOS/"
  cp "$root/src/SipProbe.Mac/Info.plist" "$app_dir/Contents/Info.plist"
  chmod +x "$app_dir/Contents/MacOS/$executable"
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$app_dir"
  fi
  echo "Built: $app_dir (v$version)"
}

zip_app() {
  local rid="$1"
  local app_dir="$root/dist/macos-${rid#osx-}/${app_name}.app"
  local zip_path="$root/dist/InspireTel-SIPProbe-macOS-${rid#osx-}.zip"
  rm -f "$zip_path"
  COPYFILE_DISABLE=1 ditto -c -k --keepParent "$app_dir" "$zip_path"
  echo "Zipped: $zip_path"
}

publish_rid osx-arm64
make_app osx-arm64
zip_app osx-arm64

if [[ "${SIPPROBE_MAC_INTEL:-0}" == "1" ]]; then
  publish_rid osx-x64
  make_app osx-x64
  zip_app osx-x64
fi
