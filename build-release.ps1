<#
.SYNOPSIS
  Builds, tests and packages DSC-Sync into dist\ (self-contained: target PCs need NOTHING else installed).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\build-release.ps1
  powershell -ExecutionPolicy Bypass -File .\build-release.ps1 -SkipTests
#>
param(
    [string]$Configuration = "Release",
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$publish = Join-Path $root "publish"
$dist = Join-Path $root "dist"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe $($arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

Remove-Item $publish, $dist -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $publish, $dist | Out-Null

Step "Restore & build solution"
Run dotnet @("build", "$root\DSC-Sync.sln", "-c", $Configuration)

if (-not $SkipTests) {
    Step "Run tests (simulated token: hot-swap, multiplexing, multi-user routing, PKCS#11 & PDF signing)"
    Run dotnet @("test", "$root\tests\DSC-Sync.Tests\DSC-Sync.Tests.csproj", "-c", $Configuration, "--no-build",
        "--blame-hang-timeout", "3m", "--logger", "console;verbosity=normal")
}

Step "Publish DSC-Sync.exe (self-contained single file, win-x64)"
Run dotnet @("publish", "$root\src\DSC-Sync.App\DSC-Sync.App.csproj", "-c", $Configuration, "-r", "win-x64",
    "--self-contained", "true", "-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:EnableCompressionInSingleFile=true", "-p:DebugType=none", "-o", "$publish\app")

Step "Publish DSC-Sync-P11.dll (NativeAOT virtual PKCS#11 module)"
Run dotnet @("publish", "$root\src\DSC-Sync.P11\DSC-Sync.P11.csproj", "-c", $Configuration, "-r", "win-x64", "-o", "$publish\p11-x64")
Copy-Item "$publish\p11-x64\DSC-Sync-P11.dll" "$publish\app\DSC-Sync-P11-x64.dll"
try {
    Run dotnet @("publish", "$root\src\DSC-Sync.P11\DSC-Sync.P11.csproj", "-c", $Configuration, "-r", "win-x86", "-o", "$publish\p11-x86")
    Copy-Item "$publish\p11-x86\DSC-Sync-P11.dll" "$publish\app\DSC-Sync-P11-x86.dll"
} catch {
    Write-Warning "32-bit PKCS#11 module not built ($_). 64-bit Acrobat/Reader and browsers are unaffected."
}

Step "Publish DSC-Sync-RdpPlugin.dll (NativeAOT mstsc channel plug-in)"
Run dotnet @("publish", "$root\src\DSC-Sync.RdpPlugin\DSC-Sync.RdpPlugin.csproj", "-c", $Configuration, "-r", "win-x64", "-o", "$publish\rdp")
Copy-Item "$publish\rdp\DSC-Sync-RdpPlugin.dll" "$publish\app\DSC-Sync-RdpPlugin.dll"

Step "Assemble dist\"
$local = Join-Path $dist "DSC-Sync-Local"
$remote = Join-Path $dist "DSC-Sync-Remote"
foreach ($d in @($local, $remote)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

Copy-Item "$publish\app\DSC-Sync.exe", "$publish\app\DSC-Sync-RdpPlugin.dll" $local
Copy-Item "$root\packaging\install-local.cmd", "$root\packaging\uninstall.cmd", "$root\packaging\INSTALL-LOCAL.txt" $local

Copy-Item "$publish\app\DSC-Sync.exe", "$publish\app\DSC-Sync-P11-*.dll" $remote
Copy-Item "$root\packaging\install-remote.cmd", "$root\packaging\install-server-all-users.cmd", "$root\packaging\uninstall.cmd", "$root\packaging\INSTALL-REMOTE.txt" $remote

Compress-Archive -Path "$local\*" -DestinationPath "$dist\DSC-Sync-Local.zip" -Force
Compress-Archive -Path "$remote\*" -DestinationPath "$dist\DSC-Sync-Remote.zip" -Force

Step "Done"
Get-ChildItem $dist -Recurse -File | ForEach-Object { "{0,-60} {1,10:N0} KB" -f $_.FullName.Substring($dist.Length + 1), ($_.Length / 1KB) }
