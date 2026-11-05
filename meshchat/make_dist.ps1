param(
  [string]$Bin = "",
  [string]$OutDir = "",
  [string]$SodiumDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not $Bin) {
  $Build = Join-Path $Root "meshchat\build-dist-win"
  $cmakeArgs = @("-S", (Join-Path $Root "meshchat"), "-B", $Build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release")
  if ($SodiumDir) { $cmakeArgs += "-DJARGONET_SODIUM_ROOT=$SodiumDir" }
  & cmake @cmakeArgs
  if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }
  & cmake --build $Build -j 4
  if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }
  $Bin = Join-Path $Build "meshchat.exe"
}

$resolved = Resolve-Path -LiteralPath $Bin -ErrorAction SilentlyContinue
if (-not $resolved) { throw "meshchat.exe not found: $Bin" }
$exe = $resolved.Path
if (-not $OutDir) { $OutDir = Join-Path $Root "dist" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Stage = Join-Path $OutDir "meshchat-windows-x86_64"
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

$bundleSource = Join-Path (Join-Path $Root "meshchat") "dist"
Copy-Item $exe (Join-Path $Stage "meshchat.exe")
Copy-Item (Join-Path $bundleSource "README.txt") (Join-Path $Stage "README.txt")
Copy-Item (Join-Path $bundleSource "run.bat") (Join-Path $Stage "run.bat")

# Explicit runtime copy makes a dynamic-libsodium build usable even when
# objdump is unavailable on the packaging host.
if ($SodiumDir) {
  $binDir = Join-Path $SodiumDir "bin"
  foreach ($pattern in @('libsodium*.dll', 'libwinpthread*.dll', 'libssp*.dll', 'libgcc*.dll', 'libstdc++*.dll')) {
    Get-ChildItem -Path $binDir -Filter $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
      Copy-Item $_.FullName (Join-Path $Stage $_.Name) -Force
      Write-Host "bundled DLL: $($_.Name)"
    }
  }
}

$systemPattern = '^(KERNEL32|USER32|ADVAPI32|WS2_32|MSWSOCK|SHELL32|OLE32|BCRYPT|NTLM|SHLWAPI|IPHLPAPI|api-ms-win-|ucrtbase|msvcrt|vcruntime|ntdll)'
$imports = @()
$objdump = Get-Command objdump -ErrorAction SilentlyContinue
if ($objdump) {
  try {
    $imports = & objdump -p $exe |
      Select-String -Pattern 'DLL Name:\s*(.+)$' |
      ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
  } catch {
    Write-Warning "objdump could not run; skipping import scan. A static build needs no extra DLLs."
    $imports = @()
  }
}

$searchDirs = @()
if ($SodiumDir) {
  $searchDirs += $SodiumDir
  $searchDirs += (Join-Path $SodiumDir "bin")
}
$searchDirs += (Split-Path -Parent $exe)
$searchDirs += ($env:PATH -split ";")
$searchDirs += "C:\msys64\ucrt64\bin"
$searchDirs = $searchDirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

foreach ($dll in $imports) {
  if ($dll -match $systemPattern) { continue }
  $source = $null
  foreach ($dir in $searchDirs) {
    $candidate = Join-Path $dir $dll
    if (Test-Path $candidate) { $source = $candidate; break }
  }
  if ($source) {
    Copy-Item $source (Join-Path $Stage (Split-Path -Leaf $source))
    Write-Host "bundled DLL: $dll"
  } else {
    Write-Warning "could not locate dependency $dll; add it beside meshchat.exe if the demo machine lacks it"
  }
}

$zip = Join-Path $OutDir "meshchat-windows-x86_64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $zip -Force
Write-Host $zip
