param(
  [string]$Bin = ".\build\meshchat.exe",
  [string]$Peers = ""
)

$resolved = Resolve-Path -LiteralPath $Bin -ErrorAction SilentlyContinue
if (-not $resolved) {
  Write-Error "meshchat binary not found: $Bin. Build it first with CMake."
  exit 1
}
$exe = $resolved.Path
$dir = Split-Path -Parent $exe

function Start-MeshNode {
  param([string]$Name, [int]$Port)

  $extra = ""
  if ($Peers) {
    $extra = " --peers '$($Peers.Replace("'", "''"))'"
  }
  $safeExe = $exe.Replace("'", "''")
  $safeDir = $dir.Replace("'", "''")
  $nodeScript = "`$Host.UI.RawUI.WindowTitle = 'meshchat - $Name'; " +
                "Set-Location -LiteralPath '$safeDir'; " +
                "& '$safeExe' --name '$Name' --port $Port$extra"
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($nodeScript))
  Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoExit", "-NoProfile", "-EncodedCommand", $encoded `
    -WindowStyle Normal | Out-Null
}

Start-MeshNode -Name "Alice" -Port 9001
Start-MeshNode -Name "Bob" -Port 9002
Start-MeshNode -Name "R1" -Port 9003
Start-MeshNode -Name "R2" -Port 9004

Write-Host "Demo ready. Alice=9001 Bob=9002 R1=9003 R2=9004. Type /peers on any node."
Write-Host "If the four windows cannot see each other, rerun with:"
Write-Host "  .\run_demo.ps1 -Peers 192.168.1.20:9001,192.168.1.21:9002,192.168.1.22:9003,192.168.1.23:9004"
