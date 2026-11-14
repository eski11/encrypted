// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This launcher is for Windows x64.');
const root = dirname(fileURLToPath(import.meta.url)), bin = join(root, 'bin');
try {
  const health = await fetch('http://127.0.0.1:9751/v1/health', { signal: AbortSignal.timeout(3000) });
  if ((await health.json()).service !== 'ENCPTD') throw new Error();
} catch { console.error('Start ENCPTD using Start-ENCPTD.cmd before opening the internet connector.'); process.exit(1); }
mkdirSync(bin, { recursive: true });
const exe = join(bin, 'cloudflared.exe'), manifest = join(bin, 'connector.json');
let verified = false;
try { const meta = JSON.parse(readFileSync(manifest, 'utf8')); verified = existsSync(exe) && createHash('sha256').update(readFileSync(exe)).digest('hex') === meta.sha256; } catch {}
if (!verified) {
  console.log('Downloading the official Windows internet connector and verifying its published SHA-256 digest...');
  const response = await fetch('https://api.github.com/repos/cloudflare/cloudflared/releases/latest', { headers: { 'user-agent': 'ENCPTD-local-server' } });
  if (!response.ok) throw new Error('Could not read the official connector release.');
  const release = await response.json(), asset = release.assets.find(a => a.name === 'cloudflared-windows-amd64.exe');
  if (!asset || !/^sha256:[a-f0-9]{64}$/.test(asset.digest)) throw new Error('The connector has no published verification digest.');
  const download = await fetch(asset.browser_download_url);
  if (!download.ok) throw new Error('Connector download failed.');
  const data = Buffer.from(await download.arrayBuffer()), sha256 = createHash('sha256').update(data).digest('hex');
  if (`sha256:${sha256}` !== asset.digest) throw new Error('Connector checksum verification failed.');
  writeFileSync(exe + '.download', data); renameSync(exe + '.download', exe);
  writeFileSync(manifest, JSON.stringify({ version: release.tag_name, sha256 }));
}
console.log('Starting a temporary HTTPS connection. Keep this window and the server running.');
console.log('Cloudflare handles this test connection and can observe login traffic/metadata. Message contents are separately end-to-end encrypted by the phone app.');
const tunnel = spawn(exe, ['tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:9751'], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let buffer = '', announced = false;
const inspect = chunk => {
  buffer = (buffer + chunk.toString()).slice(-10000);
  const url = buffer.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/)?.[0];
  if (url && !announced) {
    announced = true; writeFileSync(join(root, 'public.json'), JSON.stringify({ url }, null, 2));
    console.log(`Your temporary ENCPTD server address: ${url}`);
    console.log('Enter this address in the ENCPTD phone app. It may change when this connector restarts.');
  }
};
tunnel.stdout.on('data', inspect); tunnel.stderr.on('data', inspect);
tunnel.on('error', () => { console.error('The internet connector could not start.'); process.exitCode = 1; });
tunnel.on('exit', code => { console.log('The internet connection has stopped.'); process.exit(code ?? 1); });
process.on('SIGINT', () => tunnel.kill()); process.on('SIGTERM', () => tunnel.kill());
