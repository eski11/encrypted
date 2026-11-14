@echo off
cd /d "%~dp0"
if exist "runtime\node.exe" (
  "runtime\node.exe" "desktop\start.mjs"
) else (
  node "desktop\start.mjs"
)
if errorlevel 1 pause
