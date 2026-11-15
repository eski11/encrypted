// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Discovery, saveJSON } from './discovery.mjs';
import { probePublicRelay, TunnelHealth } from './tunnel-health.mjs';
import { setTimeout as delay } from 'node:timers/promises';

if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This launcher is for Windows x64.');
const root = dirname(fileURLToPath(import.meta.url)), bin = join(root, 'bin');
const directory = process.env.ENCPTD_DATA_DIR || join(root, 'state');
if (!existsSync(join(directory, 'discovery.json'))) {
  console.error('Run Setup-Automatic-Connection.cmd first. This app uses a signed connection file instead of a phone address field.'); process.exit(1);
}
const discovery = new Discovery(directory);
discovery.publicConfig();
const lockFile = join(directory, 'connector.lock');
if (existsSync(lockFile)) {
  let running = false;
  try { process.kill(Number(readFileSync(lockFile, 'utf8')), 0); running = true; } catch {}
  if (running) { console.error('The ENCPTD internet connector is already running. Keep its existing window open.'); process.exit(1); }
  unlinkSync(lockFile);
}
writeFileSync(lockFile, String(process.pid), { flag: 'wx', mode: 0o600 });
process.on('exit', () => { try { unlinkSync(lockFile); } catch {} });
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
console.log('The updated phone app encrypts credentials and API data to this PC inside HTTPS. Cloudflare can still see IP addresses, timing and padded traffic sizes.');
let activeTunnel, currentURL = null, lastPublished = 0, stopping = false;
const stopSignal = new AbortController();
let publications = Promise.resolve();
function publish(url) {
  publications = publications.then(async () => {
    try {
      const record = { url, updatedAt: Date.now(), published: false };
      saveJSON(join(root, 'public.json'), record);
      await discovery.publish(url);
      lastPublished = url ? Date.now() : 0;
      saveJSON(join(root, 'public.json'), { ...record, published: true });
      console.log(url ? 'Phone connection updated automatically. Open ENCPTD on the phone to sign in or create an account.' : 'Phone connection marked offline.');
    } catch (error) { console.error(error.message); console.error('The phone connection has not been updated. The connector will retry.'); }
  });
  return publications;
}
async function runTunnel() {
  const health = new TunnelHealth(), cancellation = new AbortController();
  let buffer = '', candidate = null, checking = false;
  const child = spawn(exe, ['tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:9751'], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  activeTunnel = child;
  const check = async () => {
    if (!candidate || checking || stopping || cancellation.signal.aborted) return;
    checking = true;
    try {
      const healthy = await probePublicRelay(candidate, { signal: cancellation.signal });
      if (stopping || cancellation.signal.aborted) return;
      const action = health.observe(healthy);
      if (action === 'restart') {
        console.error('The temporary connection stopped responding. Reconnecting automatically...');
        child.kill();
      } else if (healthy && (action === 'ready' || Date.now() - lastPublished > 3600000)) {
        currentURL = candidate;
        await publish(candidate);
      }
    } finally { checking = false; }
  };
  const inspect = chunk => {
    buffer = (buffer + chunk.toString()).slice(-10000);
    const url = buffer.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/)?.[0];
    if (url && !candidate && !stopping) { candidate = url; void check(); }
  };
  child.stdout.on('data', inspect); child.stderr.on('data', inspect);
  const interval = setInterval(() => { void check(); }, 15000);
  const startup = setTimeout(() => {
    if (!health.ready && !stopping) { console.error('The temporary connection did not become ready. Trying again...'); child.kill(); }
  }, 90000);
  child.on('error', () => console.error('The internet connector could not start. Retrying shortly.'));
  await new Promise(resolve => child.once('close', resolve));
  cancellation.abort(); clearInterval(interval); clearTimeout(startup);
  activeTunnel = null; currentURL = null;
}
const stop = () => { stopping = true; stopSignal.abort(); activeTunnel?.kill(); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
await publish(null);
while (!stopping) {
  await runTunnel();
  await publish(null);
  if (!stopping) { try { await delay(5000, undefined, { signal: stopSignal.signal }); } catch {} }
}
console.log('The internet connection has stopped.');
