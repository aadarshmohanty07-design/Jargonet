param(
  [string]$Bin = "",
  [string]$Peers = ""
)

$ErrorActionPreference = "Stop"

function Write-NotReady([string]$Reason) {
  Write-Host ("NOT READY: " + $Reason) -ForegroundColor Red
  exit 1
}

function Resolve-Binary {
  param([string]$Candidate)
  $resolved = Resolve-Path -LiteralPath $Candidate -ErrorAction SilentlyContinue
  if ($resolved) { return $resolved.Path }
  return $null
}

$exe = $null
if ($Bin) {
  $exe = Resolve-Binary $Bin
  if (-not $exe) { Write-NotReady "meshchat binary not found: $Bin" }
} else {
  foreach ($candidate in @(
      (Join-Path $PSScriptRoot "build\meshchat.exe"),
      (Join-Path $PSScriptRoot "..\build\root\meshchat.exe"),
      (Join-Path $PSScriptRoot "..\build\meshchat.exe"))) {
    $exe = Resolve-Binary $candidate
    if ($exe) { break }
  }
  if (-not $exe) { Write-NotReady "meshchat binary not found; build it or pass -Bin" }
}

try {
  $versionOutput = & $exe --version 2>&1
  $versionExit = $LASTEXITCODE
} catch {
  Write-NotReady "binary does not run (Smart App Control or a missing DLL may be blocking it): $($_.Exception.Message)"
}
if ($versionExit -ne 0) {
  Write-NotReady "binary does not run (Smart App Control or a missing DLL may be blocking it). Output: $versionOutput"
}

function Test-PortBusy([int]$Port) {
  $endpoints = Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue
  if ($endpoints) { return $true }
  $lines = netstat -ano -p UDP 2>$null | Select-String -Pattern (":" + $Port + "\s")
  return [bool]$lines
}

$busy = @()
foreach ($port in @(9001, 9002, 9003, 9004, 9999, 19190, 19191, 19192)) {
  if (Test-PortBusy $port) { $busy += $port }
}
if ($busy.Count -gt 0) {
  Write-NotReady ("UDP port(s) already in use: " + ($busy -join ", ") + " (stop a previous demo first)")
}

$tmp = Join-Path $env:TEMP ("meshchat-check-" + $PID)
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$processes = @()
function Stop-Processes {
  foreach ($process in $processes) {
    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
  }
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

try {
  $aOut = Join-Path $tmp "a.out"
  $aErr = Join-Path $tmp "a.err"
  $bOut = Join-Path $tmp "b.out"
  $bErr = Join-Path $tmp "b.err"
  $a = Start-Process -FilePath $exe `
    -ArgumentList @("--name", "CheckA", "--port", "19190", "--no-color", "--run-for", "8") `
    -RedirectStandardOutput $aOut -RedirectStandardError $aErr -NoNewWindow -PassThru
  $processes += $a
  $b = Start-Process -FilePath $exe `
    -ArgumentList @("--name", "CheckB", "--port", "19191", "--no-color", "--run-for", "8") `
    -RedirectStandardOutput $bOut -RedirectStandardError $bErr -NoNewWindow -PassThru
  $processes += $b
  [void]$a.WaitForExit(20000)
  [void]$b.WaitForExit(20000)
  if (-not $a.HasExited -or -not $b.HasExited) {
    Write-Host "--- CheckA ---" -ForegroundColor Yellow
    Get-Content $aOut, $aErr -ErrorAction SilentlyContinue | Select-Object -Last 20
    Write-Host "--- CheckB ---" -ForegroundColor Yellow
    Get-Content $bOut, $bErr -ErrorAction SilentlyContinue | Select-Object -Last 20
    Write-NotReady "the loopback discovery pair did not exit after --run-for"
  }
  $aText = Get-Content -Raw $aOut -ErrorAction SilentlyContinue
  $bText = Get-Content -Raw $bOut -ErrorAction SilentlyContinue
  if ($aText -notmatch "Online:.*CheckB" -or $bText -notmatch "Online:.*CheckA") {
    Write-NotReady "UDP broadcast discovery failed between two loopback instances (check the firewall and port 9999)"
  }
  $processes = @()

  if ($Peers) {
    $seedOut = Join-Path $tmp "seed.out"
    $seedErr = Join-Path $tmp "seed.err"
    $seed = Start-Process -FilePath $exe `
      -ArgumentList @("--name", "CheckSeed", "--port", "19192", "--no-color", "--no-broadcast", "--peers", $Peers, "--run-for", "8") `
      -RedirectStandardOutput $seedOut -RedirectStandardError $seedErr -NoNewWindow -PassThru
    $processes += $seed
    [void]$seed.WaitForExit(20000)
    if (-not $seed.HasExited -or $seed.ExitCode -ne 0) {
      Get-Content $seedOut, $seedErr -ErrorAction SilentlyContinue | Select-Object -Last 20
      Write-NotReady "the --peers reachability probe exited unexpectedly"
    }
    $seedText = Get-Content -Raw $seedOut -ErrorAction SilentlyContinue
    if ($seedText -notmatch "Online:") {
      Write-NotReady "no --peers seed responded (check the addresses, firewall, and that the other machines are running)"
    }
    $processes = @()
  }

  Write-Host "READY" -ForegroundColor Green
  exit 0
} catch {
  Write-Host "--- CheckA / CheckB output ---" -ForegroundColor Yellow
  Get-Content (Join-Path $tmp "a.out"), (Join-Path $tmp "a.err"), (Join-Path $tmp "b.out"), (Join-Path $tmp "b.err") -ErrorAction SilentlyContinue | Select-Object -Last 30
  Write-Host ("NOT READY: " + $_.Exception.Message) -ForegroundColor Red
  exit 1
} finally {
  Stop-Processes
}
