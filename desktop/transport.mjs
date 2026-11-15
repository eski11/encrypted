// SPDX-License-Identifier: AGPL-3.0-only
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const hpke = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
export const requestInfo = instance => Buffer.from(`ENCPTD-request-v1|${instance}`);
export const responseInfo = (instance, request) => Buffer.from(`ENCPTD-response-v1|${instance}|${request}`);
export const transportAAD = Buffer.from('ENCPTD-transport-v1');
const maximum = 3 * 1024 * 1024;
export function pack(value) {
  const json = Buffer.from(JSON.stringify(value));
  if (json.length + 4 > maximum) throw new Error('Transport payload too large.');
  const result = randomBytes(Math.ceil((json.length + 4) / 1024) * 1024);
  result.writeUInt32BE(json.length); json.copy(result, 4);
  return result;
}
export function unpack(bytes) {
  const data = Buffer.from(bytes);
  if (data.length < 1024 || data.length > maximum || data.length % 1024 !== 0) throw new Error('Invalid transport padding.');
  const length = data.readUInt32BE();
  if (length < 2 || length > data.length - 4) throw new Error('Invalid transport length.');
  return JSON.parse(data.subarray(4, 4 + length));
}
export function encodedBytes(value, min, max) {
  if (typeof value !== 'string') throw new Error('Invalid bytes.');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || bytes.length < min || bytes.length > max) throw new Error('Invalid bytes.');
  return bytes;
}
export function transportIdentity(directory) {
  mkdirSync(directory, { recursive: true });
  const file = join(directory, 'transport-key.json');
  if (!existsSync(file)) {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    writeFileSync(file, JSON.stringify({ version: 1, privateKey: privateKey.export({ format: 'jwk' }) }) + '\n', { mode: 0o600, flag: 'wx' });
  }
  const value = JSON.parse(readFileSync(file, 'utf8'));
  if (value.version !== 1 || value.privateKey?.crv !== 'P-256' || !value.privateKey.d) throw new Error('Invalid private transport key.');
  const publicKey = createPublicKey({ key: value.privateKey, format: 'jwk' }).export({ format: 'jwk' });
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(publicKey.x, 'base64url'), Buffer.from(publicKey.y, 'base64url')]);
  if (raw.length !== 65) throw new Error('Invalid transport public key.');
  return { privateKey: value.privateKey, publicKey: raw.toString('base64') };
}
export class SecureTransport {
  constructor(directory, instanceID) {
    this.instanceID = instanceID;
    this.identity = transportIdentity(directory);
    this.privateKey = hpke.kem.importKey('jwk', this.identity.privateKey, false);
  }
  async open(envelope) {
    if (envelope?.version !== 1 || Object.keys(envelope).some(k => !['version', 'enc', 'ciphertext'].includes(k))) throw new Error('Invalid encrypted request.');
    const enc = encodedBytes(envelope.enc, 65, 65), ciphertext = encodedBytes(envelope.ciphertext, 1040, 512 * 1024 + 16);
    const receiver = await hpke.createRecipientContext({ recipientKey: await this.privateKey, enc, info: requestInfo(this.instanceID) });
    const input = unpack(await receiver.open(ciphertext, transportAAD));
    if (!input || Object.keys(input).some(k => !['requestID','sentAt','method','path','token','body','replyKey'].includes(k)) ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input.requestID ?? '') ||
        !Number.isSafeInteger(input.sentAt) || Math.abs(Date.now() - input.sentAt) > 120000 ||
        !['GET','POST','PUT'].includes(input.method) || typeof input.path !== 'string' || !/^\/v1\/[a-z0-9_/-]+$/.test(input.path) || input.path.length > 128 ||
        (input.token != null && !/^[A-Za-z0-9_-]{43}$/.test(input.token))) throw new Error('Invalid encrypted request.');
    const replyKey = await hpke.kem.deserializePublicKey(encodedBytes(input.replyKey,65,65));
    const body = input.body == null ? Buffer.alloc(0) : encodedBytes(input.body,2,256 * 1024);
    return {
      input, body,
      seal: async (status, responseBody) => {
        const sender = await hpke.createSenderContext({ recipientPublicKey: replyKey, senderKey: await this.privateKey, info: responseInfo(this.instanceID,input.requestID) });
        const ciphertext = await sender.seal(pack({ requestID: input.requestID, status, body: Buffer.from(responseBody).toString('base64') }), transportAAD);
        return { version: 1, enc: Buffer.from(sender.enc).toString('base64'), ciphertext: Buffer.from(ciphertext).toString('base64') };
      }
    };
  }
}
