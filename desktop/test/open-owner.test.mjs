import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {launchOwnerBrowser} from '../open-owner.mjs';
const url='http://127.0.0.1:9752/#'+'a'.repeat(43);

test('browser handoff waits for Windows launch, with the owner address in the environment only',async()=>{
  let spawned,finished=false;
  const child=new EventEmitter();child.kill=()=>{};
  const pending=launchOwnerBrowser(url,{platform:'win32',env:{SystemRoot:'C:\\Windows'},spawnImpl:(file,args,options)=>{spawned={file,args,options};return child;}}).then(()=>{finished=true;});
  await Promise.resolve();assert.equal(finished,false);
  assert.ok(spawned.file.endsWith('powershell.exe'));
  assert.ok(!JSON.stringify(spawned.args).includes(url));
  assert.equal(spawned.options.env.ENCPTD_OWNER_URL,url);
  assert.equal(spawned.options.windowsHide,true);
  child.emit('exit',0);await pending;assert.equal(finished,true);
});
test('browser launch failures are reported instead of a false success',async()=>{
  const child=new EventEmitter();child.kill=()=>{};
  const pending=launchOwnerBrowser(url,{platform:'win32',spawnImpl:()=>child});
  child.emit('exit',1);await assert.rejects(pending,/could not open the panel/);
});
test('browser launcher rejects foreign hosts and malformed owner addresses before spawning',async()=>{
  for(const invalid of ['https://example.com/#'+'a'.repeat(43),'http://127.0.0.1:9752/?x=1#'+'a'.repeat(43),'http://127.0.0.1:9752/#bad']) {
    await assert.rejects(launchOwnerBrowser(invalid,{platform:'win32',spawnImpl:()=>{throw new Error('Must not spawn');}}),/Invalid local owner address/);
  }
});
