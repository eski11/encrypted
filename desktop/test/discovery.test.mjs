import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Discovery, lifetime } from '../discovery.mjs';

test('public discovery contains only signed connection metadata and survives restart', async () => {
  const directory = mkdtempSync(join(tmpdir(),'encptd-discovery-'));
  assert.ok(resolve(directory).startsWith(resolve(tmpdir())));
  const requests = [];
  let published, now = 1900000000000;
  const gistID = 'a'.repeat(32);
  const network = async (url, options) => {
    requests.push({url,options});
    if(url.startsWith('https://gist.githubusercontent.com/')) return new Response(JSON.stringify(published));
    assert.ok(url.startsWith('https://api.github.com/'));
    assert.equal(options.redirect,'error');
    assert.equal(options.headers.authorization,'Bearer test-token');
    published = JSON.parse(JSON.parse(options.body).files['connection.json'].content);
    return new Response(JSON.stringify({id:gistID,owner:{login:'test-owner'},public:true}));
  };
  const options = {fetchImpl:network,credentials:async ()=>'test-token',now:()=>now};
  try {
    const publisher = new Discovery(directory,options), config = await publisher.initialize();
    assert.equal(config.discoveryURL,`https://gist.githubusercontent.com/test-owner/${gistID}/raw/connection.json`);
    assert.deepEqual(Object.keys(config).sort(),['discoveryURL','instanceID','publicKey','version']);
    const privateData = JSON.parse(readFileSync(join(directory,'discovery.json'),'utf8'));
    assert.ok(privateData.privateKey.includes('PRIVATE KEY'));
    assert.ok(!JSON.stringify(requests).includes('PRIVATE KEY'));
    assert.ok(!JSON.stringify(requests).includes(privateData.privateKey));
    const key = createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(config.publicKey,'base64')]),format:'der',type:'spki'});
    let previous = 0;
    for(const url of [null,'https://first.trycloudflare.com','https://second.trycloudflare.com',null]) {
      now += 1000;
      await publisher.publish(url);
      const data = Buffer.from(published.payload,'base64'), signature = Buffer.from(published.signature,'base64');
      assert.ok(verify(null,data,key,signature));
      const payload = JSON.parse(data);
      assert.deepEqual(Object.keys(payload).sort(),['expiresAt','instanceID','issuedAt','revision','service','url','version']);
      assert.equal(payload.url,url); assert.equal(payload.instanceID,config.instanceID);
      assert.equal(payload.expiresAt-payload.issuedAt,lifetime);
      assert.ok(payload.revision>previous); previous=payload.revision;
      const tampered=Buffer.from(data); tampered[0]^=1;
      assert.equal(verify(null,tampered,key,signature),false);
    }
    const restored = new Discovery(directory,options);
    assert.deepEqual(await restored.initialize(),config);
    await restored.publish('https://restarted.trycloudflare.com');
    assert.ok((await restored.checkPublicFile()).revision>previous);
    assert.equal(requests.filter(r=>r.options?.method==='POST').length,1,'restart reuses the same public file and signing identity');
    assert.equal(requests.at(-1).options.headers,undefined,'public lookup sends no GitHub token');
    const before = restored.state.revision;
    for(const bad of ['http://unsafe.example','https://user:password@example.com','https://example.com/path','https://example.com/?token=secret']) {
      await assert.rejects(restored.publish(bad));
    }
    assert.equal(restored.state.revision,before);
  } finally { rmSync(directory,{recursive:true,force:true}); }
});

test('failed GitHub upload reserves its revision so a retry cannot roll back the phone', async () => {
  const directory=mkdtempSync(join(tmpdir(),'encptd-discovery-'));
  assert.ok(resolve(directory).startsWith(resolve(tmpdir())));
  let fail=false;
  const options={credentials:async ()=>'test-token',fetchImpl:async()=>fail?new Response('',{status:503}):new Response(JSON.stringify({id:'b'.repeat(32),owner:{login:'test-owner'},public:true}))};
  try {
    const publisher=new Discovery(directory,options); await publisher.initialize();
    fail=true; await assert.rejects(publisher.publish('https://test.trycloudflare.com'),/HTTP 503/);
    const reserved=publisher.state.revision;
    fail=false;
    const restored=new Discovery(directory,options);
    const envelope=await restored.publish(null);
    assert.ok(JSON.parse(Buffer.from(envelope.payload,'base64')).revision>reserved);
  } finally { rmSync(directory,{recursive:true,force:true}); }
});
