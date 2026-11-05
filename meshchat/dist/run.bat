@echo off
setlocal
set "MESHCHAT_DIR=%~dp0"
set "PATH=%MESHCHAT_DIR%;%MESHCHAT_DIR%lib;%PATH%"

if "%~1"=="" (
  "%MESHCHAT_DIR%meshchat.exe" --name MeshUser --port 0
) else (
  "%MESHCHAT_DIR%meshchat.exe" %*
)
endlocal
