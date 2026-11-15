@echo off
cd /d "%~dp0"
if exist runtime\node.exe (
  runtime\node.exe desktop\setup-discovery.mjs
) else (
  node desktop\setup-discovery.mjs
)
pause
