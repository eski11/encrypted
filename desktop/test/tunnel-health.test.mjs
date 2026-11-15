import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probePublicRelay, TunnelHealth } from '../tunnel-health.mjs';

test('DNS disappearance and HTTP failure cannot be advertised as a healthy connection', async () => {
  const url='https://test.trycloudflare.com';
  assert.equal(await probePublicRelay(url,{fetchImpl:async()=>{throw Object.assign(new Error('DNS record gone'),{code:'ENOTFOUND'});}}),false);
  assert.equal(await probePublicRelay(url,{fetchImpl:async()=>new Response('bad gateway',{status:502})}),false);
  assert.equal(await probePublicRelay(url,{fetchImpl:async()=>new Response(JSON.stringify({service:'other'}))}),false);
  assert.equal(await probePublicRelay(url,{fetchImpl:async(target,options)=>{
    assert.equal(target,url+'/v1/health');assert.equal(options.redirect,'error');
    assert.ok(options.signal instanceof AbortSignal);
    return new Response(JSON.stringify({service:'ENCPTD',protectedTransport:true}));
  }}),true);
});

test('brief failures recover, persistent failures restart, and replacement addresses must pass a fresh check', () => {
  const health=new TunnelHealth();
  assert.equal(health.observe(false),'waiting');
  assert.equal(health.observe(true),'ready');
  assert.equal(health.observe(false),'waiting');
  assert.equal(health.observe(false),'waiting');
  assert.equal(health.observe(true),'healthy','a successful check resets the failure streak');
  assert.equal(health.observe(false),'waiting');
  assert.equal(health.observe(false),'waiting');
  assert.equal(health.observe(false),'restart');
  const replacement=new TunnelHealth();
  assert.equal(replacement.ready,false);
  assert.equal(replacement.observe(true),'ready');
});
