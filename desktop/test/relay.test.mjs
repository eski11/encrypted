import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import { createRelay } from '../server.mjs';

test('authentication, one-time key claims, opaque queue and owner isolation', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'encptd-test-'));
  assert.equal(resolve(directory).startsWith(resolve(tmpdir())), true);
  const owner = randomBytes(32).toString('base64url');
  const relay = createRelay({ directory, adminToken: owner });
  relay.clientServer.listen(0, '127.0.0.1'); relay.adminServer.listen(0, '127.0.0.1');
  await Promise.all([once(relay.clientServer, 'listening'), once(relay.adminServer, 'listening')]);
  const client = `http://127.0.0.1:${relay.clientServer.address().port}`;
  const admin = `http://127.0.0.1:${relay.adminServer.address().port}`;
  const call = async (base, path, method='GET', data, token) => {
    const response = await fetch(base+path, { method, headers: { 'content-type':'application/json', ...(token ? { authorization:`Bearer ${token}` } : {}) }, ...(data ? { body:JSON.stringify(data) } : {}) });
    return { status:response.status, data:await response.json() };
  };
  try {
    assert.equal((await call(client,'/accounts','POST',{username:'alice',password:'a sufficiently long password'},owner)).status, 401);
    const alice = await call(admin,'/accounts','POST',{username:'alice',password:'correct horse battery staple'},owner);
    const bob = await call(admin,'/accounts','POST',{username:'bob',password:'a different long password'},owner);
    const mallory = await call(admin,'/accounts','POST',{username:'mallory',password:'another long password'},owner);
    assert.equal(alice.status,201); assert.equal(bob.status,201); assert.equal(mallory.status,201);
    assert.equal((await call(client,'/v1/login','POST',{username:'alice',password:'wrong'})).status,401);
    const login = async (username,password)=>(await call(client,'/v1/login','POST',{username,password})).data.token;
    const a = await login('alice','correct horse battery staple'), b = await login('bob','a different long password');
    const m = await login('mallory','another long password');
    const encoded=n=>randomBytes(n).toString('base64');
    const bundle=()=>({identityKey:encoded(33),registrationId:100,signedPreKey:{id:1,key:encoded(33),signature:encoded(64)},preKeys:[{id:10,key:encoded(33)}],kyberPreKeys:[{id:10,key:encoded(1569),signature:encoded(64)}]});
    const original=bundle();
    assert.equal((await call(client,'/v1/device','PUT',original,b)).status,200);
    assert.equal((await call(client,'/v1/device','PUT',bundle(),b)).status,409);
    assert.equal((await call(client,'/v1/device','PUT',bundle(),a)).status,200);
    assert.equal((await call(client,`/v1/keys/${bob.data.id}/claim`,'POST',undefined,a)).status,200);
    assert.equal((await call(client,'/v1/device','PUT',original,b)).status,200);
    assert.equal((await call(client,`/v1/keys/${bob.data.id}/claim`,'POST',undefined,a)).status,409,'re-upload cannot revive consumed keys');
    const packet={messageId:randomUUID(),recipient:bob.data.id,kind:3,ciphertext:encoded(300)};
    assert.equal((await call(client,'/v1/messages','POST',{...packet,text:'plaintext must be rejected'},a)).status,400);
    assert.equal((await call(client,'/v1/messages','POST',{...packet,kind:8},a)).status,400);
    assert.equal((await call(client,'/v1/messages','POST',packet,a)).status,200);
    assert.equal((await call(client,'/v1/messages','POST',packet,a)).status,200);
    assert.equal((await call(client,'/v1/messages','POST',{...packet,ciphertext:encoded(300)},a)).status,409);
    const inbox=await call(client,'/v1/inbox','GET',undefined,b);
    assert.equal(inbox.data.messages.length,1); assert.equal(inbox.data.messages[0].sender,alice.data.id);
    const seq=inbox.data.messages[0].seq;
    await call(client,'/v1/inbox/ack','POST',{sequences:[seq]},m);
    assert.equal((await call(client,'/v1/inbox','GET',undefined,b)).data.messages.length,1,'another user cannot acknowledge someone else’s inbox');
    await call(client,'/v1/inbox/ack','POST',{sequences:[seq]},b);
    assert.equal((await call(client,'/v1/inbox','GET',undefined,b)).data.messages.length,0);
    await call(client,'/v1/messages','POST',packet,a);
    assert.equal((await call(client,'/v1/inbox','GET',undefined,b)).data.messages.length,0,'retry after acknowledgement does not redeliver');
    await call(client,'/v1/logout','POST',{},a);
    assert.equal((await call(client,'/v1/inbox','GET',undefined,a)).status,401);
    const unauthorizedOrigin=await fetch(admin+'/accounts',{method:'POST',headers:{origin:'https://evil.example',authorization:`Bearer ${owner}`,'content-type':'application/json'},body:'{}'});
    assert.equal(unauthorizedOrigin.status,403);
    relay.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    assert.equal(readFileSync(join(directory,'encptd.sqlite')).includes(Buffer.from('correct horse battery staple')),false);
  } finally {
    await Promise.all([new Promise(r=>relay.clientServer.close(r)),new Promise(r=>relay.adminServer.close(r))]);
    relay.close(); rmSync(directory,{recursive:true,force:true});
  }
});
