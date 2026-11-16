import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
import http from 'node:http';
import { PCChat } from '../pc-chat.mjs';
const {createRelay}=await import(process.env.ENCPTD_TEST_SERVER_MODULE??'../server.mjs');

async function fixture(t,{allowLegacy=true}={}) {
  const directory=mkdtempSync(join(tmpdir(),'encptd-admin-')),phoneDirectory=mkdtempSync(join(tmpdir(),'encptd-peer-'));
  const owner=randomBytes(32).toString('base64url'),clock={value:Date.now()};
  const relay=createRelay({directory,adminToken:owner,allowLegacy,now:()=>clock.value});
  relay.adminServer.listen(0,'127.0.0.1');relay.clientServer.listen(0,'127.0.0.1');
  await Promise.all([once(relay.adminServer,'listening'),once(relay.clientServer,'listening')]);
  const admin=`http://127.0.0.1:${relay.adminServer.address().port}`,base=`http://127.0.0.1:${relay.clientServer.address().port}`;
  t.after(async()=>{await Promise.all([new Promise(r=>relay.adminServer.close(r)),new Promise(r=>relay.clientServer.close(r))]);relay.close();for(const dir of [directory,phoneDirectory]){assert.ok(resolve(dir).startsWith(resolve(tmpdir())));rmSync(dir,{recursive:true,force:true});}});
  const request=async(url,path,input,headers={})=>{
    const response=await fetch(url+path,{method:input===undefined?'GET':'POST',headers:{...(input!==undefined?{'content-type':'application/json'}:{}),...headers},...(input!==undefined?{body:JSON.stringify(input)}:{})});
    return {status:response.status,data:await response.json()};
  };
  const call=(path,input,session,headers={})=>request(admin,path,input,{authorization:`Bearer ${owner}`,...(session?{'x-encptd-chat':session}:{}),...headers});
  const api=async(path,method,input,token)=>{
    const response=await fetch(base+path,{method,headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})},...(input?{body:JSON.stringify(input)}:{})});
    const data=await response.json();if(!response.ok)throw Object.assign(new Error(data.error),{status:response.status});return data;
  };
  const phone=new PCChat({directory:phoneDirectory,api,accountExists:name=>!!relay.db.prepare('SELECT 1 FROM users WHERE username=?').get(name),now:()=>clock.value});
  t.after(()=>phone.close());
  return {directory,phoneDirectory,relay,call,request,admin,base,owner,phone,clock};
}
const passphrase='disposable PC vault passphrase 914';

test('PC chat works with production transport enforcement and never exposes admin routes on the phone port',async t=>{
  const f=await fixture(t,{allowLegacy:false});
  for(const path of ['/accounts','/pc-chat/status'])assert.equal((await f.request(f.base,path,undefined,{authorization:'Bearer '+f.owner})).status,426);
  assert.equal((await f.request(f.base,'/pc-chat/setup',{username:'attacker',passphrase},{authorization:'Bearer '+f.owner})).status,426);
  const setup=await f.call('/pc-chat/setup',{username:'pc_only',passphrase});assert.equal(setup.status,200);
  const list=await f.call('/accounts');assert.equal(list.data.accounts[0].username,'pc_only');assert.equal(list.data.accounts[0].paired,true);
});

test('administrator login is PC-only; normal accounts can retrieve only its signed public identity',async t=>{
  const f=await fixture(t);
  const pc=await f.call('/pc-chat/setup',{username:'pc_admin',passphrase});assert.equal(pc.status,200);
  const phone=await f.phone.setup({username:'normal_phone',passphrase});
  const headers={authorization:'Bearer '+f.phone.state.owner.token};
  const descriptor=await f.request(f.base,'/v1/administrator',undefined,headers);assert.equal(descriptor.status,200);
  const payload=JSON.parse(Buffer.from(descriptor.data.payload,'base64'));
  assert.equal(payload.administrator.username,'pc_admin');
  assert.deepEqual(Object.keys(payload.administrator).sort(),['id','identityKey','username']);
  assert.equal((await f.request(f.base,'/v1/login',{username:'pc_admin',password:passphrase})).status,403);
  assert.equal((await f.request(f.base,'/v1/login',{username:'normal_phone',password:passphrase})).status,200);
  assert.equal((await f.request(f.base,'/v1/register',{username:'fake_admin',password:passphrase,administrator:true})).status,400);
  assert.equal((await f.call('/pc-chat/status',undefined,pc.data.session)).data.administrator,true);
  await f.call('/pc-chat/lock',{});
  assert.equal((await f.call('/pc-chat/unlock',{passphrase})).status,200,'panel can still unlock its PC-only account');
});

test('owner account list excludes secrets; hostile origins and ordinary sessions cannot administer',async t=>{
  const f=await fixture(t);
  assert.equal((await f.call('/accounts',{username:'phone_user',password:passphrase})).status,201);
  const signed=await f.request(f.base,'/v1/login',{username:'phone_user',password:passphrase});
  assert.equal((await f.request(f.admin,'/accounts',undefined)).status,401);
  assert.equal((await f.request(f.admin,'/accounts',undefined,{authorization:'Bearer '+signed.data.token})).status,401);
  assert.equal((await f.call('/accounts',undefined,null,{origin:'https://hostile.invalid'})).status,403);
  const wrongHost=await new Promise((resolve,reject)=>{
    const req=http.get(f.admin+'/accounts',{headers:{host:'hostile.invalid',authorization:'Bearer '+f.owner}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);
  });
  assert.equal(wrongHost,403);
  const list=await f.call('/accounts');assert.equal(list.status,200);
  assert.deepEqual(Object.keys(list.data.accounts[0]).sort(),['id','paired','queued','sessions','username']);
  assert.equal(list.data.accounts[0].paired,false);assert.equal(list.data.accounts[0].sessions,1);
  assert.ok(!JSON.stringify(list.data).includes(passphrase));
  assert.equal((await f.call(`/accounts/${signed.data.id}/revoke-sessions`,{confirmed:false})).status,400);
  assert.equal((await f.call(`/accounts/${signed.data.id}/revoke-sessions`,{confirmed:true})).status,200);
  assert.equal(f.relay.db.prepare('SELECT count(*) AS n FROM sessions').get().n,0);
  assert.equal((await f.request(f.base,'/pc-chat/status',undefined,{authorization:'Bearer '+f.owner})).status,401);
  assert.equal((await f.call('/pc-chat/setup',{username:'phone_user',passphrase})).status,409,'PC chat cannot replace an existing phone account');
});

test('PC and peer verify symmetric safety numbers, exchange real Signal messages and retain encrypted state across relock',async t=>{
  const f=await fixture(t),bob=await f.phone.setup({username:'phone_bob',passphrase});
  const setup=await f.call('/pc-chat/setup',{username:'pc_alice',passphrase});assert.equal(setup.status,200);const session=setup.data.session;
  const a=await f.call('/pc-chat/contact',{username:'phone_bob'},session),b=await f.phone.contact(bob.session,{username:'pc_alice'});
  assert.equal(a.status,200);assert.match(a.data.number,/^\d{60}$/);assert.equal(a.data.number,b.number);
  await assert.rejects(f.phone.send(bob.session,{username:'pc_alice',text:'ordinary unverified sender blocked',messageID:randomUUID()}),/Compare and verify/);
  assert.equal((await f.call('/pc-chat/verify',{username:'phone_bob',identityKey:a.data.identityKey,compared:false},session)).status,400);
  assert.equal((await f.call('/pc-chat/verify',{username:'phone_bob',identityKey:randomBytes(33).toString('base64'),compared:true},session)).status,409);
  await f.phone.verify(bob.session,{username:'pc_alice',identityKey:b.identityKey,compared:true});
  const text='private PC message 3491 <script>alert(1)</script>',messageID=randomUUID();
  const sent=await f.call('/pc-chat/send',{username:'phone_bob',text,messageID},session);assert.equal(sent.status,200);assert.equal(sent.data.queued,false);
  const queued=f.relay.db.prepare('SELECT ciphertext,kind FROM messages').get();assert.equal(queued.kind,3);assert.ok(!Buffer.from(queued.ciphertext).includes(Buffer.from(text)));
  const peer=await f.phone.sync(bob.session);assert.equal(peer.messages[0].text,text);assert.ok(Math.abs(peer.messages[0].date-f.clock.value)<1000);assert.equal(peer.messages[0].expiresAt-f.clock.value,86400000);
  assert.equal((await f.call('/pc-chat/send',{username:'phone_bob',text,messageID},session)).status,200);
  assert.equal((await f.phone.sync(bob.session)).messages.length,1,'same ID retry cannot duplicate a ratchet message');
  await f.phone.send(bob.session,{username:'pc_alice',text:'private phone reply 294',messageID:randomUUID()});
  const synced=await f.call('/pc-chat/sync',{},session);assert.equal(synced.status,200);assert.equal(synced.data.messages.at(-1).text,'private phone reply 294');
  const vault=readFileSync(join(f.directory,'pc-chat.vault.json'),'utf8');assert.ok(!vault.includes(text));assert.ok(!vault.includes(passphrase));assert.ok(!vault.includes('private phone reply 294'));
  assert.equal((await f.call('/pc-chat/status',undefined,randomBytes(32).toString('base64url'))).data.unlocked,false);
  await f.call('/pc-chat/lock',{});
  assert.equal((await f.call('/pc-chat/sync',{},session)).status,423);
  assert.equal((await f.call('/pc-chat/unlock',{passphrase:'this is the wrong passphrase'})).status,403);
  const unlocked=await f.call('/pc-chat/unlock',{passphrase});assert.equal(unlocked.status,200);assert.notEqual(unlocked.data.session,session);
  const restored=await f.call('/pc-chat/status',undefined,unlocked.data.session);assert.equal(restored.data.messages.length,2);assert.equal(restored.data.messages.at(-1).text,'private phone reply 294');
  assert.equal((await f.call('/pc-chat/contact',{username:'phone_bob'},unlocked.data.session)).data.number,a.data.number);
  const changed=Buffer.concat([Buffer.from([5]),randomBytes(32)]).toString('base64');
  f.relay.db.prepare('UPDATE devices SET identity=? WHERE user_id=?').run(changed,a.data.id);
  assert.equal((await f.call('/pc-chat/send',{username:'phone_bob',text:'changed recipient must be blocked',messageID:randomUUID()},unlocked.data.session)).status,409);
});

test('administrator can receive registered-user replies without contact setup; polling cannot extend unlock deadline',async t=>{
  const f=await fixture(t),peer=await f.phone.setup({username:'phone_bob',passphrase});
  const setup=await f.call('/pc-chat/setup',{username:'pc_alice',passphrase}),session=setup.data.session;
  const a=await f.call('/pc-chat/contact',{username:'phone_bob'},session),b=await f.phone.contact(peer.session,{username:'pc_alice'});
  await f.phone.verify(peer.session,{username:'pc_alice',identityKey:b.identityKey,compared:true});
  await f.phone.send(peer.session,{username:'pc_alice',text:'waiting for verification',messageID:randomUUID()});
  const incoming=await f.call('/pc-chat/sync',{},session);assert.equal(incoming.status,200);assert.equal(incoming.data.unverified,0);assert.equal(incoming.data.messages.length,1);
  assert.equal(f.relay.db.prepare('SELECT count(*) AS n FROM messages').get().n,0);
  assert.equal(incoming.data.messages[0].text,'waiting for verification');
  f.clock.value+=4*60000;assert.equal((await f.call('/pc-chat/sync',{},session)).status,200);
  f.clock.value+=60001;assert.equal((await f.call('/pc-chat/sync',{},session)).status,423);
  assert.deepEqual((await f.call('/pc-chat/status',undefined,session)).data,{configured:true,unlocked:false});
});
