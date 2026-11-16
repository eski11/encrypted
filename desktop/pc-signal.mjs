// SPDX-License-Identifier: AGPL-3.0-only
import * as S from '@signalapp/libsignal-client';
import { randomInt } from 'node:crypto';
const b64 = bytes => Buffer.from(bytes).toString('base64');
const raw = value => Buffer.from(value, 'base64');
export const swiftEpoch = 978307200000;

export function newPCIdentity(username) {
  return {version:1,username,identity:b64(S.PrivateKey.generate().serialize()),registrationID:randomInt(1,16384),nextKeyID:2,
    signed:{},preKeys:{},kyber:{},usedKyber:[],sessions:{},trusted:{},contacts:{},messages:[],outbox:[],received:[],owner:null};
}
export function signalStores(state) {
  const key = S.PrivateKey.deserialize(raw(state.identity));
  const session = new class extends S.SessionStore {
    async saveSession(address,record) { state.sessions[address.name()]=b64(record.serialize()); }
    async getSession(address) { const value=state.sessions[address.name()];return value?S.SessionRecord.deserialize(raw(value)):null; }
    async getExistingSessions(addresses) { return Promise.all(addresses.map(async a=>{const r=await this.getSession(a);if(!r)throw new Error('Session missing.');return r;})); }
  };
  const identity = new class extends S.IdentityKeyStore {
    async getIdentityKey() { return key; }
    async getLocalRegistrationId() { return state.registrationID; }
    async isTrustedIdentity(address,other) { return state.trusted[address.name()]===b64(other.serialize()); }
    async saveIdentity(address,other) { if(!await this.isTrustedIdentity(address,other))throw new Error('Compare safety numbers before messaging.');return S.IdentityChange.NewOrUnchanged; }
    async getIdentity(address) { const value=state.trusted[address.name()];return value?S.PublicKey.deserialize(raw(value)):null; }
  };
  const preKey = new class extends S.PreKeyStore {
    async savePreKey(id,record) { state.preKeys[id]=b64(record.serialize()); }
    async getPreKey(id) { if(!state.preKeys[id])throw new Error('Pre-key missing.');return S.PreKeyRecord.deserialize(raw(state.preKeys[id])); }
    async removePreKey(id) { delete state.preKeys[id]; }
  };
  const signed = new class extends S.SignedPreKeyStore {
    async saveSignedPreKey(id,record) { state.signed[id]=b64(record.serialize()); }
    async getSignedPreKey(id) { if(!state.signed[id])throw new Error('Signed key missing.');return S.SignedPreKeyRecord.deserialize(raw(state.signed[id])); }
  };
  const kyber = new class extends S.KyberPreKeyStore {
    async saveKyberPreKey(id,record) { state.kyber[id]=b64(record.serialize()); }
    async getKyberPreKey(id) { if(!state.kyber[id])throw new Error('Kyber key missing.');return S.KyberPreKeyRecord.deserialize(raw(state.kyber[id])); }
    async markKyberPreKeyUsed(id,signedID,baseKey) {
      const marker=`${id}:${signedID}:${b64(baseKey.serialize())}`;
      if(state.usedKyber.includes(marker))throw new Error('Repeated encrypted session rejected.');
      state.usedKyber.push(marker);
    }
  };
  return {session,identity,preKey,signed,kyber,key};
}
export function preparePCKeys(state,count=25) {
  const identity=S.PrivateKey.deserialize(raw(state.identity));
  if(!state.signed[1]) {
    const key=S.PrivateKey.generate();
    state.signed[1]=b64(S.SignedPreKeyRecord.new(1,Date.now(),key.getPublicKey(),key,identity.sign(key.getPublicKey().serialize())).serialize());
  }
  for(let n=0;n<count;n++) {
    const id=state.nextKeyID++,key=S.PrivateKey.generate(),pq=S.KEMKeyPair.generate();
    state.preKeys[id]=b64(S.PreKeyRecord.new(id,key.getPublicKey(),key).serialize());
    state.kyber[id]=b64(S.KyberPreKeyRecord.new(id,Date.now(),pq,identity.sign(pq.getPublicKey().serialize())).serialize());
  }
}
export function pcPublication(state) {
  const signed=S.SignedPreKeyRecord.deserialize(raw(state.signed[1]));
  const publicItem=record=>({id:record.id(),key:b64(record.publicKey().serialize())});
  const sorted=values=>values.sort((a,b)=>b.id-a.id).slice(0,100);
  return {identityKey:b64(S.PrivateKey.deserialize(raw(state.identity)).getPublicKey().serialize()),registrationId:state.registrationID,
    signedPreKey:{...publicItem(signed),signature:b64(signed.signature())},
    preKeys:sorted(Object.values(state.preKeys).map(v=>publicItem(S.PreKeyRecord.deserialize(raw(v))))),
    kyberPreKeys:sorted(Object.values(state.kyber).map(v=>{const r=S.KyberPreKeyRecord.deserialize(raw(v));return {...publicItem(r),signature:b64(r.signature())};}))};
}
export function pcSafetyNumber(state,contact) {
  return S.Fingerprint.new(5200,2,Buffer.from(state.owner.id),S.PrivateKey.deserialize(raw(state.identity)).getPublicKey(),
    Buffer.from(contact.id),S.PublicKey.deserialize(raw(contact.identityKey))).displayableFingerprint().toString();
}
export async function pcEncrypt(state,contact,text,messageID,claim,now=Date.now()) {
  const stores=signalStores(state),address=S.ProtocolAddress.new(contact.id,1),local=S.ProtocolAddress.new(state.owner.id,1);
  if(!(await stores.session.getSession(address))?.hasCurrentState()) {
    const b=await claim();
    if(b.identityKey!==contact.identityKey)throw new Error('Recipient key changed. Compare safety numbers again.');
    const bundle=S.PreKeyBundle.new(b.registrationId,1,b.preKey.id,S.PublicKey.deserialize(raw(b.preKey.key)),b.signedPreKey.id,
      S.PublicKey.deserialize(raw(b.signedPreKey.key)),raw(b.signedPreKey.signature),S.PublicKey.deserialize(raw(b.identityKey)),
      b.kyberPreKey.id,S.KEMPublicKey.deserialize(raw(b.kyberPreKey.key)),raw(b.kyberPreKey.signature));
    await S.processPreKeyBundle(bundle,address,local,stores.session,stores.identity);
  }
  const clear=Buffer.from(JSON.stringify({version:1,text,created:(now-swiftEpoch)/1000,expiresAt:(now+86400000-swiftEpoch)/1000}));
  const cipher=await S.signalEncrypt(clear,address,local,stores.session,stores.identity);
  if(![2,3].includes(cipher.type()))throw new Error('Unsupported encrypted message.');
  return {messageId:messageID,recipient:contact.id,kind:cipher.type(),ciphertext:b64(cipher.serialize())};
}
export async function pcDecrypt(state,packet) {
  const s=signalStores(state),address=S.ProtocolAddress.new(packet.sender,1),local=S.ProtocolAddress.new(state.owner.id,1);
  let bytes;
  if(packet.kind===3)bytes=await S.signalDecryptPreKey(S.PreKeySignalMessage.deserialize(raw(packet.ciphertext)),address,local,s.session,s.identity,s.preKey,s.signed,s.kyber);
  else if(packet.kind===2)bytes=await S.signalDecrypt(S.SignalMessage.deserialize(raw(packet.ciphertext)),address,local,s.session,s.identity);
  else throw new Error('Unencrypted message rejected.');
  const value=JSON.parse(Buffer.from(bytes).toString('utf8'));
  if(value.version!==1||typeof value.text!=='string'||Buffer.byteLength(value.text)>8192||!Number.isFinite(value.created)||!Number.isFinite(value.expiresAt)||value.expiresAt<value.created)throw new Error('Invalid message content.');
  return {text:value.text,date:value.created*1000+swiftEpoch,expiresAt:value.expiresAt*1000+swiftEpoch};
}
