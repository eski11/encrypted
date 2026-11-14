@echo off
cd /d "%~dp0"
if exist "runtime\node.exe" (
  "runtime\node.exe" "desktop\stop.mjs"
) else (
  node "desktop\stop.mjs"
)
