$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$project = Join-Path $root "src/SipProbe.App/SipProbe.App.csproj"
$output = Join-Path $root "dist/win-x64"

dotnet run --project (Join-Path $root "tests/SipProbe.SelfTest/SipProbe.SelfTest.csproj") -c Release
dotnet publish $project `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -o $output

Write-Host "Built: $(Join-Path $output 'InspireTel.SIPProbe.exe')"
