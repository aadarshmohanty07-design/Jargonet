param(
  [string]$Bin = ".\build\meshchat.exe"
)

$resolved = Resolve-Path -LiteralPath $Bin -ErrorAction SilentlyContinue
if (-not $resolved) {
  Write-Error "meshchat binary not found: $Bin. Build it first with CMake."
  exit 1
}
$exe = $resolved.Path

Start-Process -FilePath $exe -ArgumentList "--name", "Alice",  "--port", "9001"
Start-Process -FilePath $exe -ArgumentList "--name", "Bob",    "--port", "9002"
Start-Process -FilePath $exe -ArgumentList "--name", "Relay1", "--port", "9003"
Start-Process -FilePath $exe -ArgumentList "--name", "Relay2", "--port", "9004"

Write-Host "Four meshchat windows launched (Alice, Bob, Relay1, Relay2)."
Write-Host "Wait for the Online lines, then try in Alice:"
Write-Host "  send Bob hi --relays 2 --verbose-route"
