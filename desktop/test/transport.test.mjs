import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
const { createRelay } = await import(process.env.ENCPTD_TEST_SERVER_MODULE ?? '../server.mjs');
import { hpke, pack, unpack, requestInfo, responseInfo, transportAAD, transportIdentity } from '../transport.mjs';
import { Discovery } from '../discovery.mjs';

test('pinned HPKE protects credentials and responses, rejects replay, tampering and plaintext downgrade', async () => {
  const directory=mkdtempSync(join(tmpdir(),'encptd-channel-'));
  assert.ok(resolve(directory).startsWith(resolve(tmpdir())));
  const relay=createRelay({directory,adminToken:randomBytes(32).toString('base64url')});
  relay.clientServer.listen(0,'127.0.0.1'); await once(relay.clientServer,'listening');
  const base=`http://127.0.0.1:${relay.clientServer.address().port}`;
  const instance=new Discovery(directory).state.instanceID;
  const serverPublic=await hpke.kem.deserializePublicKey(Buffer.from(transportIdentity(directory).publicKey,'base64'));
  const wire=async body=>{const r=await fetch(base+'/v2/transport',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});return {status:r.status,data:await r.json()};};
  const prepare=async(path,method='GET',body,token,changes={})=>{
    const replyKeys=await hpke.kem.generateKeyPair(), requestID=randomUUID();
    const input={requestID,sentAt:Date.now(),path,method,replyKey:Buffer.from(await hpke.kem.serializePublicKey(replyKeys.publicKey)).toString('base64'),...changes};
    if(body)input.body=Buffer.from(JSON.stringify(body)).toString('base64'); if(token)input.token=token;
    const sender=await hpke.createSenderContext({recipientPublicKey:serverPublic,info:requestInfo(instance)});
    const ciphertext=await sender.seal(pack(input),transportAAD);
    return {envelope:{version:1,enc:Buffer.from(sender.enc).toString('base64'),ciphertext:Buffer.from(ciphertext).toString('base64')},
      async decode(envelope,publicKey=serverPublic){
        const recipient=await hpke.createRecipientContext({recipientKey:replyKeys.privateKey,senderPublicKey:publicKey,enc:Buffer.from(envelope.enc,'base64'),info:responseInfo(instance,requestID)});
        const reply=unpack(await recipient.open(Buffer.from(envelope.ciphertext,'base64'),transportAAD));
        assert.equal(reply.requestID,requestID);
        return {status:reply.status,data:JSON.parse(Buffer.from(reply.body,'base64'))};
      }};
  };
  const call=async(...args)=>{const p=await prepare(...args),response=await wire(p.envelope);assert.equal(response.status,200);return p.decode(response.data);};
  try {
    const secret='do not disclose this password';
    const registration=await prepare('/v1/register','POST',{username:'secure_user',password:secret});
    assert.ok(!JSON.stringify(registration.envelope).includes(secret));
    assert.ok(!JSON.stringify(registration.envelope).includes('secure_user'));
    const response=await wire(registration.envelope); assert.equal(response.status,200);
    const registered=await registration.decode(response.data);
    assert.equal(registered.status,201); assert.equal(registered.data.username,'secure_user');
    assert.ok(!JSON.stringify(response).includes(registered.data.token));
    const attackerKeys=await hpke.kem.generateKeyPair();
    await assert.rejects(registration.decode(response.data,attackerKeys.publicKey),'wrong server response key must fail');
    assert.equal((await wire(registration.envelope)).status,409,'replaying signup does not repeat side effects');
    const tampered={...registration.envelope};const ct=Buffer.from(tampered.ciphertext,'base64');ct[0]^=1;tampered.ciphertext=ct.toString('base64');
    assert.equal((await wire(tampered)).status,400);
    assert.equal((await call('/v1/device','GET',null,registered.data.token)).status,200);
    assert.equal((await call('/v1/inbox','GET',null,'x'.repeat(43))).status,401,'errors are encrypted too');
    assert.equal((await wire((await prepare('/accounts','POST',{})).envelope)).status,400,'owner paths cannot enter the transport');
    assert.equal((await wire((await prepare('/v1/inbox','GET',null,null,{sentAt:Date.now()-121000})).envelope)).status,400,'stale encrypted requests fail');
    assert.equal((await fetch(base+'/v1/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'downgrade',password:secret})})).status,426,'no plaintext fallback');
    assert.equal((await fetch(base+'/v1/inbox',{headers:{authorization:`Bearer ${registered.data.token}`}})).status,426);
    assert.equal((await call('/v1/password','POST',{oldPassword:'wrong',newPassword:'a different secure password'},registered.data.token)).status,403);
    const changed=await call('/v1/password','POST',{oldPassword:secret,newPassword:'a different secure password'},registered.data.token);
    assert.equal(changed.status,200);
    assert.equal(changed.data.id,registered.data.id);
    assert.equal((await call('/v1/device','GET',null,registered.data.token)).status,401,'changing password revokes previous sessions');
    assert.equal((await call('/v1/device','GET',null,changed.data.token)).status,200);
    assert.equal((await call('/v1/login','POST',{username:'secure_user',password:secret})).status,401);
    assert.equal((await call('/v1/login','POST',{username:'secure_user',password:'a different secure password'})).status,200);
    relay.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    assert.equal(readFileSync(join(directory,'encptd.sqlite')).includes(Buffer.from(secret)),false);
  } finally {
    await new Promise(r=>relay.clientServer.close(r)); relay.close();rmSync(directory,{recursive:true,force:true});
  }
});

test('queued ciphertext and retry metadata expire without deleting accounts', async () => {
  const directory=mkdtempSync(join(tmpdir(),'encptd-retention-'));
  assert.ok(resolve(directory).startsWith(resolve(tmpdir())));
  const now=Date.now(), relay=createRelay({directory,adminToken:randomBytes(32).toString('base64url'),allowLegacy:true,now:()=>now});
  relay.clientServer.listen(0,'127.0.0.1');await once(relay.clientServer,'listening');
  try {
    const sender=randomUUID(),recipient=randomUUID(),token=randomBytes(32).toString('base64url');
    for(const [id,name] of [[sender,'sender'],[recipient,'recipient']]) relay.db.prepare('INSERT INTO users VALUES(?,?,?,?)').run(id,name,randomBytes(16),randomBytes(32));
    relay.db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(createHash('sha256').update(token).digest('hex'),recipient,now+86400000);
    for(const days of [8,1]) relay.db.prepare('INSERT INTO messages(sender,recipient,message_id,kind,ciphertext,created) VALUES(?,?,?,?,?,?)').run(sender,recipient,randomUUID(),3,randomBytes(100),now-days*86400000);
    for(const days of [31,29]) relay.db.prepare('INSERT INTO dedup VALUES(?,?,?,?,?)').run(sender,randomUUID(),'','hash',now-days*86400000);
    relay.db.prepare('INSERT INTO transport_replays VALUES(?,?)').run(randomUUID(),now-1);
    const r=await fetch(`http://127.0.0.1:${relay.clientServer.address().port}/v1/inbox`,{headers:{authorization:`Bearer ${token}`}});
    assert.equal(r.status,200);assert.equal((await r.json()).messages.length,1);
    assert.equal(relay.db.prepare('SELECT count(*) AS n FROM dedup').get().n,1);
    assert.equal(relay.db.prepare('SELECT count(*) AS n FROM transport_replays').get().n,0);
    assert.equal(relay.db.prepare('SELECT count(*) AS n FROM users').get().n,2);
  } finally { await new Promise(r=>relay.clientServer.close(r));relay.close();rmSync(directory,{recursive:true,force:true}); }
});
