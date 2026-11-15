// SPDX-License-Identifier: AGPL-3.0-only
import { createHash, randomBytes, createPublicKey, verify, timingSafeEqual } from 'node:crypto';

const hash = value => createHash('sha256').update(value).digest('hex');
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const validID = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9-]{27}$/.test(value);
const token = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
function matches(value, digest) {
  return token(value) && typeof digest === 'string' && digest.length === 64 && timingSafeEqual(Buffer.from(hash(value)), Buffer.from(digest));
}
function fields(input, allowed) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(k => !allowed.includes(k))) fail(400,'Invalid account-security request.');
}
export class AccountSecurity {
  constructor(db, { now = () => Date.now(), verifyPassword }) {
    this.db = db; this.now = now; this.verifyPassword = verifyPassword;
    db.exec(`CREATE TABLE IF NOT EXISTS account_security(user_id TEXT PRIMARY KEY REFERENCES users(id), version INTEGER NOT NULL, days INTEGER, wipe INTEGER NOT NULL, signer TEXT NOT NULL, last_unlock INTEGER NOT NULL, delete_hash TEXT, unlock_hash TEXT NOT NULL, commit_hash TEXT NOT NULL,last_event INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS account_security_pending(user_id TEXT PRIMARY KEY REFERENCES users(id), version INTEGER NOT NULL, days INTEGER, wipe INTEGER NOT NULL, signer TEXT NOT NULL, prepared INTEGER NOT NULL, delete_hash TEXT, unlock_hash TEXT NOT NULL, commit_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS account_unlock_challenges(nonce_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),version INTEGER NOT NULL,expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS account_security_changes(user_id TEXT PRIMARY KEY REFERENCES users(id),token_hash TEXT NOT NULL,expires INTEGER NOT NULL,version INTEGER NOT NULL);`);
  }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value=fn();this.db.exec('COMMIT');return value; }
    catch(error) {this.db.exec('ROLLBACK');throw error;}
  }
  policy(userID) {
    const row=this.db.prepare('SELECT * FROM account_security WHERE user_id=?').get(userID);
    return row ? {version:row.version,wipeAfterThree:!!row.wipe,inactivityDays:row.days,lastUnlockAt:row.last_unlock,deadline:row.days==null?null:row.last_unlock+row.days*86400000} : {version:0,wipeAfterThree:false,inactivityDays:null,lastUnlockAt:null,deadline:null};
  }
  deleteAccount(userID) {
    this.transaction(()=>{
      this.db.prepare('DELETE FROM messages WHERE sender=? OR recipient=?').run(userID,userID);
      this.db.prepare('DELETE FROM dedup WHERE sender=? OR recipient=?').run(userID,userID);
      for(const table of ['account_unlock_challenges','account_security_changes','account_security_pending','account_security','sessions','prekeys','devices']) this.db.prepare(`DELETE FROM ${table} WHERE user_id=?`).run(userID);
      this.db.prepare('DELETE FROM users WHERE id=?').run(userID);
    });
  }
  cleanup() {
    this.db.prepare('DELETE FROM account_unlock_challenges WHERE expires<=?').run(this.now());
    this.db.prepare('DELETE FROM account_security_changes WHERE expires<=?').run(this.now());
    const expired=this.db.prepare('SELECT user_id FROM account_security WHERE days IS NOT NULL AND last_unlock+days*86400000<=?').all(this.now());
    for(const row of expired) this.deleteAccount(row.user_id);
  }
  async prepare(userID, input) {
    fields(input,['password','wipeAfterThree','inactivityDays','signingPublicKey','changeToken']);
    if(typeof input.wipeAfterThree!=='boolean' || (input.inactivityDays!==null && (!Number.isInteger(input.inactivityDays)||input.inactivityDays<1||input.inactivityDays>365))) fail(400,'Choose an inactivity period from 1 to 365 days.');
    const signer=typeof input.signingPublicKey==='string'?Buffer.from(input.signingPublicKey,'base64'):Buffer.alloc(0);
    if(signer.length!==32||signer.toString('base64')!==input.signingPublicKey) fail(400,'Invalid unlock public key.');
    await this.verifyPassword(userID,input.password);
    this.cleanup();
    if(!this.db.prepare('SELECT 1 FROM users WHERE id=?').get(userID)) fail(410,'This account was deleted.');
    const active=this.db.prepare('SELECT version FROM account_security WHERE user_id=?').get(userID)?.version??0;
    if(active) {
      const grant=this.db.prepare('SELECT * FROM account_security_changes WHERE user_id=? AND version=? AND expires>?').get(userID,active,this.now());
      if(!grant||!matches(input.changeToken,grant.token_hash)) fail(403,'Unlock the saved account with its app passcode before changing security settings.');
    }
    const pending=this.db.prepare('SELECT version FROM account_security_pending WHERE user_id=?').get(userID)?.version??0;
    const version=Math.max(active,pending)+1, commitToken=randomBytes(32).toString('base64url'), unlockToken=randomBytes(32).toString('base64url');
    const deleteToken=input.wipeAfterThree||input.inactivityDays!==null?randomBytes(32).toString('base64url'):null;
    const preparedAt=this.now();
    this.db.prepare('INSERT INTO account_security_pending VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,days=excluded.days,wipe=excluded.wipe,signer=excluded.signer,prepared=excluded.prepared,delete_hash=excluded.delete_hash,unlock_hash=excluded.unlock_hash,commit_hash=excluded.commit_hash').run(userID,version,input.inactivityDays,Number(input.wipeAfterThree),input.signingPublicKey,preparedAt,deleteToken?hash(deleteToken):null,hash(unlockToken),hash(commitToken));
    return {version,preparedAt,commitToken,unlockToken,deleteToken};
  }
  confirm(input) {
    fields(input,['accountID','commitToken']);
    if(!validID(input.accountID)||!token(input.commitToken)) fail(400,'Invalid settings confirmation.');
    this.cleanup();
    const pending=this.db.prepare('SELECT * FROM account_security_pending WHERE user_id=?').get(input.accountID);
    if(pending&&matches(input.commitToken,pending.commit_hash)) {
      this.transaction(()=>{
        this.db.prepare('INSERT INTO account_security VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,days=excluded.days,wipe=excluded.wipe,signer=excluded.signer,last_unlock=excluded.last_unlock,delete_hash=excluded.delete_hash,unlock_hash=excluded.unlock_hash,commit_hash=excluded.commit_hash,last_event=0').run(pending.user_id,pending.version,pending.days,pending.wipe,pending.signer,pending.prepared,pending.delete_hash,pending.unlock_hash,pending.commit_hash,0);
        this.db.prepare('DELETE FROM account_security_pending WHERE user_id=?').run(input.accountID);
        this.db.prepare('DELETE FROM account_unlock_challenges WHERE user_id=?').run(input.accountID);
        this.db.prepare('DELETE FROM account_security_changes WHERE user_id=?').run(input.accountID);
      });
      this.cleanup();
    } else {
      const active=this.db.prepare('SELECT commit_hash FROM account_security WHERE user_id=?').get(input.accountID);
      if(!active||!matches(input.commitToken,active.commit_hash)) {
        if(!this.db.prepare('SELECT 1 FROM users WHERE id=?').get(input.accountID)) fail(410,'This account was deleted.');
        fail(403,'Settings confirmation was rejected.');
      }
    }
    if(!this.db.prepare('SELECT 1 FROM users WHERE id=?').get(input.accountID)) fail(410,'This account was deleted.');
    return this.policy(input.accountID);
  }
  challenge(input) {
    fields(input,['accountID','unlockToken']);this.cleanup();
    if(!validID(input.accountID)||!token(input.unlockToken)) fail(400,'Invalid unlock request.');
    const row=this.db.prepare('SELECT * FROM account_security WHERE user_id=?').get(input.accountID);
    if(!row) {
      if(!this.db.prepare('SELECT 1 FROM users WHERE id=?').get(input.accountID)) fail(410,'This account was deleted.');
      fail(409,'Security settings are not confirmed.');
    }
    if(!matches(input.unlockToken,row.unlock_hash)) fail(403,'Unlock request was rejected.');
    if(this.db.prepare('SELECT count(*) AS n FROM account_unlock_challenges WHERE user_id=?').get(input.accountID).n>=8) fail(429,'Try unlocking again shortly.');
    const nonce=randomBytes(32).toString('base64url'),expiresAt=this.now()+120000;
    this.db.prepare('INSERT INTO account_unlock_challenges VALUES(?,?,?,?)').run(hash(nonce),input.accountID,row.version,expiresAt);
    return {nonce,version:row.version,expiresAt};
  }
  unlock(input) {
    fields(input,['accountID','nonce','signature','counter']);this.cleanup();
    if(!validID(input.accountID)||!token(input.nonce)||!Number.isSafeInteger(input.counter)||input.counter<1) fail(400,'Invalid unlock proof.');
    const row=this.db.prepare('SELECT * FROM account_security WHERE user_id=?').get(input.accountID);
    if(!row) fail(410,'This account was deleted or its security settings were removed.');
    const challenge=this.db.prepare('SELECT * FROM account_unlock_challenges WHERE nonce_hash=? AND user_id=? AND version=? AND expires>?').get(hash(input.nonce),input.accountID,row.version,this.now());
    if(!challenge) fail(403,'The unlock challenge expired or was already used.');
    const signature=typeof input.signature==='string'?Buffer.from(input.signature,'base64'):Buffer.alloc(0);
    const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(row.signer,'base64')]),format:'der',type:'spki'});
    const message=Buffer.from(`ENCPTD-unlock-v1|${input.accountID}|${input.nonce}|${row.version}|${input.counter}`);
    if(signature.length!==64||signature.toString('base64')!==input.signature||!verify(null,message,publicKey,signature)) fail(403,'The unlock proof was rejected.');
    const changeToken=randomBytes(32).toString('base64url');
    this.transaction(()=>{
      this.db.prepare('DELETE FROM account_unlock_challenges WHERE nonce_hash=?').run(hash(input.nonce));
      if(input.counter>row.last_event) this.db.prepare('UPDATE account_security SET last_unlock=?,last_event=? WHERE user_id=?').run(this.now(),input.counter,input.accountID);
      this.db.prepare('INSERT INTO account_security_changes VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires=excluded.expires,version=excluded.version').run(input.accountID,hash(changeToken),this.now()+120000,row.version);
    });
    return {...this.policy(input.accountID),changeToken};
  }
  destroy(input) {
    fields(input,['accountID','deleteToken']);
    if(!validID(input.accountID)||!token(input.deleteToken)) fail(400,'Invalid account-deletion request.');
    if(!this.db.prepare('SELECT 1 FROM users WHERE id=?').get(input.accountID)) return {ok:true};
    const active=this.db.prepare('SELECT delete_hash FROM account_security WHERE user_id=?').get(input.accountID);
    const pending=this.db.prepare('SELECT delete_hash FROM account_security_pending WHERE user_id=?').get(input.accountID);
    if(!matches(input.deleteToken,active?.delete_hash)&&!matches(input.deleteToken,pending?.delete_hash)) fail(403,'Account deletion was not authorized.');
    this.deleteAccount(input.accountID);return {ok:true};
  }
}
