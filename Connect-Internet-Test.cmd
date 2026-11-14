@echo off
cd /d "%~dp0"
if exist "runtime\node.exe" (
  "runtime\node.exe" "desktop\tunnel.mjs"
) else (
  node "desktop\tunnel.mjs"
)
if errorlevel 1 pause
