// SPDX-License-Identifier: AGPL-3.0-only
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchOwnerBrowser } from './open-owner.mjs';
import { createRelay } from './server.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const directory = process.env.ENCPTD_DATA_DIR || join(root, 'state');
mkdirSync(directory, { recursive: true });
const tokenFile = join(directory, 'owner-token');
if (!existsSync(tokenFile)) writeFileSync(tokenFile, randomBytes(32).toString('base64url'), { mode: 0o600, flag: 'wx' });
const token = readFileSync(tokenFile, 'utf8').trim();
if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Invalid owner token file.');
const openOwner = async () => {
  if (!process.argv.includes('--no-browser')) await launchOwnerBrowser(`http://127.0.0.1:9752/#${token}`);
};
let existing = false;
try { const response = await fetch('http://127.0.0.1:9751/v1/health', { signal: AbortSignal.timeout(500) }); existing = (await response.json()).service === 'ENCPTD'; } catch {}
if (existing) {
  const response=await fetch('http://127.0.0.1:9752/connection',{headers:{authorization:`Bearer ${token}`},signal:AbortSignal.timeout(3000)});
  if(!response.ok)throw new Error('Another ENCPTD server folder is already running. Open the launcher from the original server folder.');
  await openOwner();console.log('ENCPTD is already running. Browser launch completed.');process.exit(0);
}
const relay = createRelay({ directory, adminToken: token, adminPage: readFileSync(join(root, 'owner.html'), 'utf8'), onShutdown: () => stop(), automaticConnection: () => {
  try { const value = JSON.parse(readFileSync(join(root, 'public.json'), 'utf8')); return value.published === true && !!value.url && Date.now() - value.updatedAt < 2 * 3600000; }
  catch { return false; }
}, getPublicURL: () => {
  try { const value = JSON.parse(readFileSync(join(root, 'public.json'), 'utf8')).url; return new URL(value).protocol === 'https:' ? value : null; }
  catch { return null; }
} });
relay.clientServer.listen(9751, '127.0.0.1', () => console.log('ENCPTD message relay is running on this PC.'));
relay.adminServer.listen(9752, '127.0.0.1', () => {
  console.log('ENCPTD owner console is local to this PC. Close this window to stop the server.');
  void openOwner().catch(error=>console.error(error.message));
});
for (const server of [relay.clientServer, relay.adminServer]) server.on('error', error => {
  console.error(error.code === 'EADDRINUSE' ? 'ENCPTD is already running, or its local ports are in use.' : 'ENCPTD could not start.');
  process.exit(1);
});
const stop = () => { relay.clientServer.close(); relay.adminServer.close(); relay.close(); process.exit(0); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
