// SPDX-License-Identifier: AGPL-3.0-only
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { transportIdentity } from './transport.mjs';

export const lifetime = 24 * 60 * 60;
export function saveJSON(path, value) {
  writeFileSync(path + '.tmp', JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  renameSync(path + '.tmp', path);
}
export function serverOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) throw new Error('Invalid HTTPS connection address.');
  return url.origin;
}
export function githubToken() {
  return new Promise((resolve, reject) => {
    const child = execFile('git', ['-c', 'credential.interactive=false', 'credential', 'fill'], {
      windowsHide: true, timeout: 15000, maxBuffer: 65536,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never' }
    }, (error, stdout) => {
      const token = stdout?.split(/\r?\n/).find(line => line.startsWith('password='))?.slice(9);
      if (error || !token) reject(new Error('GitHub sign-in is unavailable. Sign in using Git for Windows with permission to update Gists, then restart the connector.'));
      else resolve(token);
    });
    child.stdin.on('error', () => {});
    child.stdin.end('protocol=https\nhost=github.com\n\n');
  });
}

// The private signing key stays in the server's state directory. Only publicConfig()
// and signedEnvelope() are suitable for publication or inclusion in an app build.
export class Discovery {
  constructor(directory, { fetchImpl = fetch, credentials = githubToken, now = () => Date.now() } = {}) {
    mkdirSync(directory, { recursive: true });
    this.file = join(directory, 'discovery.json');
    this.transportKey = transportIdentity(directory).publicKey;
    this.fetch = fetchImpl; this.credentials = credentials; this.now = now;
    if (!existsSync(this.file)) {
      const { privateKey } = generateKeyPairSync('ed25519');
      const value = { instanceID: randomUUID(), privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }), revision: 0 };
      writeFileSync(this.file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    }
    this.reload();
  }
  reload() {
    this.state = JSON.parse(readFileSync(this.file, 'utf8'));
    this.key = createPrivateKey(this.state.privateKey);
    if (this.key.asymmetricKeyType !== 'ed25519' || !Number.isSafeInteger(this.state.revision) || this.state.revision < 0 || !/^[a-f0-9-]{36}$/.test(this.state.instanceID)) throw new Error('Invalid server discovery identity. Restore its original state directory.');
  }
  publicKey() { return createPublicKey(this.key).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'); }
  publicConfig() {
    const { gistID, owner, instanceID } = this.state;
    if (!/^[a-f0-9]{20,64}$/.test(gistID ?? '') || !/^[a-zA-Z0-9-]+$/.test(owner ?? '')) throw new Error('Automatic connection has not been set up.');
    return { version: 1, instanceID, publicKey: this.publicKey(), discoveryURL: `https://gist.githubusercontent.com/${owner}/${gistID}/raw/connection.json`, transportKey: this.transportKey };
  }
  signedEnvelope(url) {
    this.reload();
    const issuedAt = Math.floor(this.now() / 1000);
    const payload = Buffer.from(JSON.stringify({ version: 1, service: 'ENCPTD', instanceID: this.state.instanceID,
      revision: this.state.revision + 1, issuedAt, expiresAt: issuedAt + lifetime, url: url == null ? null : serverOrigin(url) }));
    // Reserve the sequence before uploading, including failed attempts.
    this.state.revision++;
    saveJSON(this.file, this.state);
    return { payload: payload.toString('base64'), signature: sign(null, payload, this.key).toString('base64') };
  }
  async api(path, method, value) {
    const token = await this.credentials();
    const response = await this.fetch('https://api.github.com' + path, {
      method, redirect: 'error', signal: AbortSignal.timeout(20000),
      headers: { accept: 'application/vnd.github+json', 'content-type': 'application/json',
        'user-agent': 'ENCPTD-local-server', 'X-GitHub-Api-Version': '2022-11-28', authorization: `Bearer ${token}` },
      body: JSON.stringify(value)
    });
    if (!response.ok) throw new Error(`GitHub connection update failed (HTTP ${response.status}). Check GitHub sign-in and Gist permission.`);
    return response.json();
  }
  async initialize() {
    if (this.state.gistID) return this.publicConfig();
    const envelope = this.signedEnvelope(null);
    const gist = await this.api('/gists', 'POST', { description: 'ENCPTD signed server connection (public connection metadata only)', public: true,
      files: { 'connection.json': { content: JSON.stringify(envelope) + '\n' } } });
    if (!gist.public || !/^[a-f0-9]{20,64}$/.test(gist.id ?? '') || !/^[a-zA-Z0-9-]+$/.test(gist.owner?.login ?? '')) throw new Error('GitHub returned an invalid connection file.');
    this.state.gistID = gist.id; this.state.owner = gist.owner.login;
    saveJSON(this.file, this.state);
    return this.publicConfig();
  }
  async publish(url) {
    this.publicConfig();
    const envelope = this.signedEnvelope(url);
    await this.api('/gists/' + this.state.gistID, 'PATCH', { files: { 'connection.json': { content: JSON.stringify(envelope) + '\n' } } });
    return envelope;
  }
  async checkPublicFile() {
    const config = this.publicConfig();
    const response = await this.fetch(config.discoveryURL + '?check=' + this.now(), { redirect: 'error', signal: AbortSignal.timeout(20000) });
    if (!response.ok) throw new Error('Public connection file is not yet available. Try again shortly.');
    const envelope = await response.json(), payload = Buffer.from(envelope.payload, 'base64');
    if (!verify(null, payload, createPublicKey(this.key), Buffer.from(envelope.signature, 'base64'))) throw new Error('The published connection signature is invalid.');
    const connection = JSON.parse(payload);
    if (connection.instanceID !== config.instanceID || connection.expiresAt <= this.now() / 1000 || connection.revision < this.state.revision) throw new Error('GitHub has not served the current connection record yet. Try again shortly.');
    return connection;
  }
}
