import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
const {createRelay}=await import(process.env.ENCPTD_TEST_SERVER_MODULE??'../server.mjs');

async function fixture(t) {
  const directory=mkdtempSync(join(tmpdir(),'encptd-auto-delete-'));assert.ok(resolve(directory).startsWith(resolve(tmpdir())));
  const clock={value:Date.now()},options={directory,adminToken:randomBytes(32).toString('base64url'),allowLegacy:true,now:()=>clock.value};
  const relay=createRelay(options);relay.clientServer.listen(0,'127.0.0.1');await once(relay.clientServer,'listening');
  let closed=false;
  const close=async()=>{if(!closed){closed=true;await new Promise(r=>relay.clientServer.close(r));relay.close();}};
  t.after(async()=>{await close();rmSync(directory,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${relay.clientServer.address().port}`;
  const call=async(path,data,token,method='POST')=>{
    const r=await fetch(base+path,{method,headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})},...(data?{body:JSON.stringify(data)}:{})});
    return {status:r.status,data:await r.json()};
  };
  const password='a unique password for testing';
  const a=(await call('/v1/register',{username:'account_alpha',password})).data;
  const b=(await call('/v1/register',{username:'account_beta',password})).data;
  const keys=generateKeyPairSync('ed25519'),publicKey=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
  const prepare=(who,changes={})=>call('/v1/security/prepare',{password,wipeAfterThree:true,inactivityDays:3,signingPublicKey:publicKey,...changes},who.token);
  const confirm=(who,prepared)=>call('/v1/security/confirm',{accountID:who.id,commitToken:prepared.commitToken});
  const unlock=async(who,prepared,counter=1)=>{
    const challenge=await call('/v1/security/challenge',{accountID:who.id,unlockToken:prepared.unlockToken});
    if(challenge.status!==200)return challenge;
    const input={accountID:who.id,nonce:challenge.data.nonce,counter,signature:sign(null,Buffer.from(`ENCPTD-unlock-v1|${who.id}|${challenge.data.nonce}|${challenge.data.version}|${counter}`),keys.privateKey).toString('base64')};
    return {...await call('/v1/security/unlock',input),proof:input};
  };
  return {relay,clock,options,close,call,a,b,prepare,confirm,unlock,password,publicKey};
}

test('destructive settings stay off by default and require password plus saved-device proof for later changes',async t=>{
  const f=await fixture(t),{call,a,prepare,confirm,clock,unlock}=f;
  assert.equal((await call('/v1/security',null,a.token,'GET')).data.inactivityDays,null);
  assert.equal((await prepare(a,{password:'wrong'})).status,403);
  assert.equal((await prepare(a,{inactivityDays:0})).status,400);
  assert.equal((await prepare(a,{inactivityDays:366})).status,400);
  const pending=await prepare(a);assert.equal(pending.status,200);
  assert.equal((await call('/v1/security',null,a.token,'GET')).data.version,0,'preparing cannot activate deletion before phone settings are durable');
  const activated=await confirm(a,pending.data);assert.equal(activated.status,200);
  assert.equal(activated.data.deadline,pending.data.preparedAt+3*86400000);
  clock.value+=86400000;
  assert.equal((await confirm(a,pending.data)).data.lastUnlockAt,pending.data.preparedAt,'retrying confirmation cannot extend the deadline');
  assert.equal((await prepare(a,{inactivityDays:null,wipeAfterThree:false})).status,403,'password alone cannot bypass the saved account passcode');
  const proof=await unlock(a,pending.data);assert.equal(proof.status,200);
  assert.equal(proof.data.lastUnlockAt,clock.value);
  const off=await prepare(a,{inactivityDays:null,wipeAfterThree:false,changeToken:proof.data.changeToken});
  assert.equal(off.status,200);assert.equal((await confirm(a,off.data)).status,200);
  assert.equal((await call('/v1/security/destroy',{accountID:a.id,deleteToken:pending.data.deleteToken})).status,403,'turning deletion off revokes the old deletion capability');
  clock.value+=400*86400000;
  await call('/v1/health',null,null,'GET');
  assert.equal(f.relay.db.prepare('SELECT count(*) AS n FROM users WHERE id=?').get(a.id).n,1,'disabled rules never delete the account');
});

test('only fresh signed passcode events reset inactivity; ordinary traffic and duplicate events do not',async t=>{
  const f=await fixture(t),{a,b,prepare,confirm,clock,call,unlock}=f;
  const prepared=(await prepare(a)).data;await confirm(a,prepared);
  clock.value+=86400000;
  await call('/v1/device',null,a.token,'GET');
  assert.equal((await call('/v1/security',null,a.token,'GET')).data.lastUnlockAt,prepared.preparedAt);
  const nonce=await call('/v1/security/challenge',{accountID:a.id,unlockToken:prepared.unlockToken});
  assert.equal((await call('/v1/security/unlock',{accountID:a.id,nonce:nonce.data.nonce,counter:1,signature:randomBytes(64).toString('base64')})).status,403);
  assert.equal((await call('/v1/security/challenge',{accountID:b.id,unlockToken:prepared.unlockToken})).status,409);
  const good=await unlock(a,prepared,1);assert.equal(good.status,200);
  assert.equal((await call('/v1/security/unlock',good.proof)).status,403,'a consumed nonce cannot be replayed');
  const last=good.data.lastUnlockAt;
  clock.value+=86400000;
  assert.equal((await unlock(a,prepared,1)).data.lastUnlockAt,last,'retrying one passcode event cannot become a keepalive');
  assert.equal((await unlock(a,prepared,2)).data.lastUnlockAt,clock.value,'a new passcode event resets the deadline');
  clock.value+=3*86400000;
  assert.equal((await call('/v1/security/challenge',{accountID:a.id,unlockToken:prepared.unlockToken})).status,410,'an expired account cannot be revived by a late unlock');
  assert.equal(f.relay.db.prepare('SELECT count(*) AS n FROM users WHERE id=?').get(b.id).n,1);
});

test('wrong-code deletion capability removes only its own account and revokes all its server data',async t=>{
  const f=await fixture(t),{relay,a,b,call,prepare}=f;
  const pending=(await prepare(a,{inactivityDays:null})).data;
  relay.db.prepare('INSERT INTO devices VALUES(?,?,?,?)').run(a.id,'test-public-key',1,'{}');
  relay.db.prepare('INSERT INTO prekeys VALUES(?,?,?,?,?)').run(a.id,'ec',1,'{}',0);
  for(const [sender,recipient] of [[a.id,b.id],[b.id,a.id]])relay.db.prepare('INSERT INTO messages(sender,recipient,message_id,kind,ciphertext,created) VALUES(?,?,?,?,?,?)').run(sender,recipient,randomUUID(),3,randomBytes(40),f.clock.value);
  assert.equal((await call('/v1/security/destroy',{accountID:b.id,deleteToken:pending.deleteToken})).status,403);
  const request={accountID:a.id,deleteToken:pending.deleteToken};
  assert.equal((await call('/v1/security/destroy',request)).status,200,'a prepared opt-in can be honoured if the phone wiped before confirmation completed');
  assert.equal((await call('/v1/security/destroy',request)).status,200,'queued offline deletion retries are idempotent');
  for(const table of ['users','sessions','devices','prekeys','account_security_pending','account_security','account_unlock_challenges','account_security_changes']){
    const column=table==='users'?'id':'user_id';assert.equal(relay.db.prepare(`SELECT count(*) AS n FROM ${table} WHERE ${column}=?`).get(a.id).n,0);
  }
  assert.equal(relay.db.prepare('SELECT count(*) AS n FROM messages').get().n,0);
  assert.equal((await call('/v1/device',null,a.token,'GET')).status,401);
  assert.equal((await call('/v1/device',null,b.token,'GET')).status,200);
  const replacement=await call('/v1/register',{username:'account_alpha',password:f.password});
  assert.equal(replacement.status,201);assert.notEqual(replacement.data.id,a.id);
  assert.equal((await call('/v1/security/destroy',request)).status,200);
  assert.equal((await call('/v1/device',null,replacement.data.token,'GET')).status,200,'an old queued deletion cannot erase a replacement account with the same username');
});

test('server restart enforces an elapsed inactivity deadline before accepting logins',async t=>{
  const f=await fixture(t),prepared=(await f.prepare(f.a,{inactivityDays:1})).data;
  await f.confirm(f.a,prepared);await f.close();
  f.clock.value+=86400000;
  const restarted=createRelay(f.options);
  try {
    assert.equal(restarted.db.prepare('SELECT count(*) AS n FROM users WHERE id=?').get(f.a.id).n,0);
    assert.equal(restarted.db.prepare('SELECT count(*) AS n FROM users WHERE id=?').get(f.b.id).n,1);
  }finally{restarted.close();}
});
