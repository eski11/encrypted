import { readFileSync } from 'node:fs';
const value = JSON.parse(readFileSync(new URL('../iphone/Resources/Server.json', import.meta.url), 'utf8'));
const url = new URL(value.discoveryURL);
if (value.version !== 1 || !/^[a-f0-9-]{36}$/.test(value.instanceID) || Buffer.from(value.publicKey, 'base64').length !== 32 ||
    url.protocol !== 'https:' || url.hostname !== 'gist.githubusercontent.com' || url.port || url.username || url.password || url.search || url.hash ||
    !/^\/[A-Za-z0-9-]+\/[a-f0-9]{20,64}\/raw\/connection\.json$/.test(url.pathname) ||
    Object.keys(value).some(key => !['version','instanceID','publicKey','discoveryURL'].includes(key))) {
  throw new Error('Include only the public configuration from Setup-Automatic-Connection.cmd in iphone/Resources/Server.json.');
}
console.log('Public automatic-connection configuration validated. No server address entry is required.');
