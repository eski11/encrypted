import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createPublicKey,verify,randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {PrivateKey} from '@signalapp/libsignal-client';
import {Administrator,administratorDomain} from '../administrator.mjs';

test('only the designated PC identity receives a signed scoped administrator certificate; deletion revokes it',()=>{
  const db=new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON;CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT);CREATE TABLE devices(user_id TEXT PRIMARY KEY REFERENCES users(id),identity TEXT);');
    const keys=generateKeyPairSync('ed25519'),instanceID=randomUUID(),now=1900000000000;
    const issuer=new Administrator(db,{state:{instanceID},key:keys.privateKey},{now:()=>now});
    const decode=envelope=>{
      const payload=Buffer.from(envelope.payload,'base64'),signature=Buffer.from(envelope.signature,'base64');
      assert.ok(verify(null,Buffer.concat([administratorDomain,payload]),keys.publicKey,signature));
      assert.equal(verify(null,payload,keys.publicKey,signature),false,'connection signatures cannot be reused as admin certificates');
      return JSON.parse(payload);
    };
    assert.equal(decode(issuer.envelope()).administrator,null);
    const id=randomUUID(),imposter=randomUUID(),identityKey=Buffer.from(PrivateKey.generate().getPublicKey().serialize()).toString('base64');
    db.prepare('INSERT INTO users VALUES(?,?)').run(id,'pc_only');db.prepare('INSERT INTO devices VALUES(?,?)').run(id,identityKey);
    db.prepare('INSERT INTO users VALUES(?,?)').run(imposter,'administrator');
    issuer.bind({id},identityKey);const active=decode(issuer.envelope());
    assert.equal(active.instanceID,instanceID);assert.equal(active.service,'ENCPTD-administrator');assert.equal(active.expiresAt-active.issuedAt,3600);
    assert.equal(active.revision,1);assert.equal(active.administrator.id,id);assert.equal(active.administrator.identityKey,identityKey);
    assert.equal(issuer.isAdministrator(imposter),false);assert.equal(issuer.isAdministrator(id),true);
    issuer.bind({id},identityKey);assert.equal(decode(issuer.envelope()).revision,1,'ordinary unlock does not rotate the admin identity');
    assert.throws(()=>issuer.bind({id},Buffer.alloc(33).toString('base64')),/not paired/);
    db.prepare('DELETE FROM devices WHERE user_id=?').run(id);db.prepare('DELETE FROM users WHERE id=?').run(id);
    const revoked=decode(issuer.envelope());assert.equal(revoked.administrator,null);assert.equal(revoked.revision,2);
  } finally {db.close();}
});
