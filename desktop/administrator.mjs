// SPDX-License-Identifier: AGPL-3.0-only
import { sign } from 'node:crypto';
export const administratorDomain=Buffer.from('ENCPTD-administrator-v1\0');

export class Administrator {
  constructor(db,discovery,{now=()=>Date.now()}={}) {
    this.db=db;this.discovery=discovery;this.now=now;
    db.exec(`CREATE TABLE IF NOT EXISTS administrator_binding(slot INTEGER PRIMARY KEY CHECK(slot=1),account_id TEXT REFERENCES users(id),identity TEXT,revision INTEGER NOT NULL);
      INSERT OR IGNORE INTO administrator_binding VALUES(1,NULL,NULL,0);
      CREATE TRIGGER IF NOT EXISTS revoke_administrator_before_delete BEFORE DELETE ON users BEGIN
        UPDATE administrator_binding SET account_id=NULL,identity=NULL,revision=revision+1 WHERE account_id=OLD.id;
      END;`);
  }
  isAdministrator(id) {return this.db.prepare('SELECT account_id FROM administrator_binding WHERE slot=1').get().account_id===id;}
  bind(owner,identityKey) {
    const device=this.db.prepare('SELECT identity FROM devices WHERE user_id=?').get(owner.id);
    if(device?.identity!==identityKey)throw new Error('The PC administrator identity is not paired correctly.');
    const old=this.db.prepare('SELECT * FROM administrator_binding WHERE slot=1').get();
    if(old.account_id!==owner.id||old.identity!==identityKey) {
      if(old.revision>=Number.MAX_SAFE_INTEGER)throw new Error('Administrator revision limit reached.');
      this.db.prepare('UPDATE administrator_binding SET account_id=?,identity=?,revision=revision+1 WHERE slot=1').run(owner.id,identityKey);
    }
  }
  envelope() {
    const binding=this.db.prepare('SELECT * FROM administrator_binding WHERE slot=1').get();
    const admin=binding.account_id?this.db.prepare('SELECT u.id,u.username,d.identity AS identityKey FROM users u JOIN devices d ON d.user_id=u.id WHERE u.id=?').get(binding.account_id):null;
    const valid=admin?.identityKey===binding.identity?admin:null,issuedAt=Math.floor(this.now()/1000);
    const payload=Buffer.from(JSON.stringify({version:1,service:'ENCPTD-administrator',instanceID:this.discovery.state.instanceID,
      revision:binding.revision,issuedAt,expiresAt:issuedAt+3600,administrator:valid??null}));
    return {payload:payload.toString('base64'),signature:sign(null,Buffer.concat([administratorDomain,payload]),this.discovery.key).toString('base64')};
  }
}
