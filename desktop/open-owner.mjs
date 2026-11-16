// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from 'node:child_process';
import { join } from 'node:path';

export const browserCommand = `
$ErrorActionPreference = 'Stop'
$programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
$candidates = @(
  (Join-Path $env:ProgramFiles 'Google\\Chrome\\Application\\chrome.exe'),
  (Join-Path $programFilesX86 'Google\\Chrome\\Application\\chrome.exe'),
  (Join-Path $programFilesX86 'Microsoft\\Edge\\Application\\msedge.exe'),
  (Join-Path $env:ProgramFiles 'Microsoft\\Edge\\Application\\msedge.exe')
)
$browser = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($browser) {
  Start-Process -FilePath $browser -ArgumentList @('--new-window', $env:ENCPTD_OWNER_URL) -ErrorAction Stop
} else {
  Start-Process -FilePath $env:ENCPTD_OWNER_URL -ErrorAction Stop
}
`;

export async function launchOwnerBrowser(url, { platform=process.platform, spawnImpl=spawn, env=process.env }={}) {
  if(platform!=='win32')return;
  const parsed=new URL(url);
  if(parsed.origin!=='http://127.0.0.1:9752'||parsed.pathname!=='/'||parsed.search||!/^#[A-Za-z0-9_-]{43}$/.test(parsed.hash))throw new Error('Invalid local owner address.');
  const executable=join(env.SystemRoot||'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe');
  await new Promise((resolve,reject)=>{
    const child=spawnImpl(executable,['-NoProfile','-NonInteractive','-Command',browserCommand],{
      windowsHide:true,stdio:'ignore',env:{...env,ENCPTD_OWNER_URL:url}
    });
    const timer=setTimeout(()=>{child.kill();reject(new Error('Browser launch timed out. Check that Chrome or Edge can open normally.'));},15000);
    child.once('error',()=>{clearTimeout(timer);reject(new Error('Windows could not start the browser launcher.'));});
    child.once('exit',code=>{clearTimeout(timer);if(code===0)resolve();else reject(new Error('Windows could not open the panel. Check that Chrome or Edge can open normally, then try again.'));});
  });
}
