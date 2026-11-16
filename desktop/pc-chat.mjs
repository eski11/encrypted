// SPDX-License-Identifier: AGPL-3.0-only
import { randomBytes, createCipheriv, createDecipheriv, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { newPCIdentity, preparePCKeys, pcPublication, pcSafetyNumber, pcEncrypt, pcDecrypt } from './pc-signal.mjs';
const derive=promisify(scrypt),aad=Buffer.from('ENCPTD-PC-chat-v1');
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};
const password=value=>{if(typeof value!=='string'||value.length<12||value.length>256)fail(400,'Use a PC chat passphrase of 12–256 characters.');return value;};
const encoded=value=>Buffer.from(value,'base64');
const fixed=(value,length)=>{if(typeof value!=='string'||encoded(value).length!==length||encoded(value).toString('base64')!==value)throw new Error('Invalid vault.');return encoded(value);};
const kdf=(passphrase,salt)=>derive(passphrase,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});

export class PCChat {
  constructor({directory,api,accountExists,now=()=>Date.now()}) {
    this.file=join(directory,'pc-chat.vault.json');this.api=api;this.accountExists=accountExists;this.now=now;
    this.queue=Promise.resolve();this.state=null;this.key=null;this.session=null;this.deadline=0;
    this.timer=setInterval(()=>{this.enqueue(()=>{if(this.state&&this.now()>=this.deadline)this.dropMemory();});},10000);
    this.timer.unref();
  }
  enqueue(work) { const value=this.queue.then(work);this.queue=value.catch(()=>{});return value; }
  dropMemory() { this.key?.fill(0);this.key=null;this.state=null;this.session=null;this.deadline=0; }
  close() {clearInterval(this.timer);this.dropMemory();}
  authorized(session) {
    if(this.state&&this.now()>=this.deadline)this.dropMemory();
    return !!this.state&&typeof session==='string'&&/^[A-Za-z0-9_-]{43}$/.test(session)&&
      timingSafeEqual(Buffer.from(session),Buffer.from(this.session));
  }
  touch() { this.deadline=this.now()+5*60000; }
  persist() {
    const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key,nonce);cipher.setAAD(aad);
    const data=Buffer.from(JSON.stringify(this.state));
    if(data.length>8*1024*1024)fail(507,'PC chat vault is full.');
    const ciphertext=Buffer.concat([cipher.update(data),cipher.final()]);
    const envelope={version:1,salt:this.salt.toString('base64'),nonce:nonce.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')};
    const temp=this.file+'.'+randomBytes(8).toString('hex')+'.tmp';
    try { writeFileSync(temp,JSON.stringify(envelope),{mode:0o600,flag:'wx'});renameSync(temp,this.file); }
    catch(error) { try {unlinkSync(temp);}catch{} throw error; }
  }
  async resume(passphrase) {
    if(!this.state.owner) {
      let owner;
      try {owner=await this.api('/v1/register','POST',{username:this.state.username,password:passphrase});}
      catch(error) {if(error.status!==409)throw error;owner=await this.api('/v1/login','POST',{username:this.state.username,password:passphrase});}
      this.state.owner=owner;this.persist();
    } else {
      const owner=await this.api('/v1/login','POST',{username:this.state.username,password:passphrase});
      if(owner.id!==this.state.owner.id)fail(409,'PC chat account changed. Keep the original vault; do not reset its keys.');
      this.state.owner=owner;this.persist();
    }
    if(!this.state.signed[1]) {preparePCKeys(this.state);this.persist();}
    await this.call('/v1/device','PUT',pcPublication(this.state));
    this.session=randomBytes(32).toString('base64url');this.touch();
    return {configured:true,unlocked:true,session:this.session,username:this.state.username};
  }
  setup({username,passphrase}) {return this.enqueue(async()=>{
    if(existsSync(this.file))fail(409,'PC chat is already configured. Unlock it with its passphrase.');
    if(typeof username!=='string'||!/^[a-z0-9_]{3,32}$/.test(username))fail(400,'Choose 3–32 lowercase letters, digits or underscores.');
    password(passphrase);
    if(this.accountExists(username))fail(409,'Choose a new PC chat username, separate from your phone accounts.');
    this.salt=randomBytes(16);this.key=await kdf(passphrase,this.salt);this.state=newPCIdentity(username);
    try {this.persist();return await this.resume(passphrase);}
    catch(error) {this.dropMemory();throw error;}
  });}
  unlock({passphrase}) {return this.enqueue(async()=>{
    password(passphrase);
    if(!existsSync(this.file))fail(404,'Set up PC chat first.');
    this.dropMemory();
    try {
      const bytes=readFileSync(this.file);if(bytes.length>12*1024*1024)throw new Error('Invalid vault.');
      const value=JSON.parse(bytes);
      if(value.version!==1||typeof value.ciphertext!=='string')throw new Error('Invalid vault.');
      this.salt=fixed(value.salt,16);this.key=await kdf(passphrase,this.salt);
      const decipher=createDecipheriv('aes-256-gcm',this.key,fixed(value.nonce,12));decipher.setAAD(aad);decipher.setAuthTag(fixed(value.tag,16));
      this.state=JSON.parse(Buffer.concat([decipher.update(encoded(value.ciphertext)),decipher.final()]).toString('utf8'));
      if(this.state.version!==1||typeof this.state.identity!=='string'||!Array.isArray(this.state.messages))throw new Error('Invalid vault.');
    } catch {this.dropMemory();fail(403,'PC chat passphrase is incorrect, or its encrypted vault is damaged.');}
    try {return await this.resume(passphrase);}catch(error){this.dropMemory();throw error;}
  });}
  lock() {return this.enqueue(()=>{this.dropMemory();return {ok:true};});}
  call(path,method='GET',body) {return this.api(path,method,body,this.state.owner.token);}
  expire() {
    const old=this.state.messages.length,now=this.now();
    this.state.messages=this.state.messages.filter(m=>m.expiresAt>now);
    this.state.outbox=this.state.outbox.filter(p=>this.state.messages.some(m=>m.id===p.messageId));
    if(old!==this.state.messages.length)this.persist();
  }
  snapshot() {return {configured:true,unlocked:true,username:this.state.username,accountID:this.state.owner.id,
    contacts:Object.values(this.state.contacts).map(c=>({id:c.id,username:c.username,verified:this.state.trusted[c.id]===c.identityKey})),
    messages:this.state.messages,queued:this.state.outbox.length,unverified:this.unverified??0,expiresAt:this.deadline};}
  status(session) {return this.enqueue(()=>{
    if(!this.authorized(session))return {configured:existsSync(this.file),unlocked:false};
    this.expire();return this.snapshot();
  });}
  work(session,action,{touch=true}={}) {return this.enqueue(async()=>{
    if(!this.authorized(session))fail(423,'Unlock PC chat with its passphrase.');
    if(touch)this.touch();this.expire();return action();
  });}
  async lookup(username) {
    if(typeof username!=='string'||!/^[a-z0-9_]{3,32}$/.test(username))fail(400,'Select an account.');
    const contact=await this.call('/v1/users/'+username);
    if(contact.id===this.state.owner.id)fail(400,'Select another account.');
    return contact;
  }
  contact(session,{username}) {return this.work(session,async()=>{
    const contact=await this.lookup(username);
    return {...contact,number:pcSafetyNumber(this.state,contact),verified:this.state.trusted[contact.id]===contact.identityKey};
  });}
  verify(session,{username,identityKey,compared}) {return this.work(session,async()=>{
    if(compared!==true)fail(400,'Compare every safety-number digit on both devices first.');
    const contact=await this.lookup(username);
    if(contact.identityKey!==identityKey)fail(409,'This key changed. Load and compare the new safety number.');
    const before=structuredClone(this.state);
    try {
      if(this.state.trusted[contact.id]&&this.state.trusted[contact.id]!==contact.identityKey)delete this.state.sessions[contact.id];
      this.state.trusted[contact.id]=contact.identityKey;this.state.contacts[contact.id]=contact;this.persist();
    } catch(error) {this.state=before;throw error;}
    return {ok:true};
  });}
  async flush() {
    for(const packet of [...this.state.outbox]) {
      await this.call('/v1/messages','POST',packet);
      const before=structuredClone(this.state);
      try {
        this.state.outbox=this.state.outbox.filter(p=>p.messageId!==packet.messageId);
        const m=this.state.messages.find(m=>m.id===packet.messageId);if(m)m.pending=false;
        this.persist();
      } catch(error) {this.state=before;throw error;}
    }
  }
  send(session,{username,text,messageID}) {return this.work(session,async()=>{
    if(typeof text!=='string'||!text.trim()||Buffer.byteLength(text)>8192)fail(400,'Send 1–8192 bytes of text.');
    if(typeof messageID!=='string'||!/^[a-f0-9]{8}-[a-f0-9-]{27}$/.test(messageID))fail(400,'Invalid message ID.');
    const contact=await this.lookup(username);
    if(this.state.trusted[contact.id]!==contact.identityKey)fail(409,'Compare and verify the current safety number before sending.');
    const old=this.state.messages.find(m=>m.id===messageID);
    if(old&&(old.contactID!==contact.id||old.text!==text||!old.outgoing))fail(409,'Message ID conflict.');
    if(!old) {
      if(this.state.messages.length>=1000||this.state.outbox.length>=100)fail(429,'PC inbox is full. Wait for messages to expire or queued sends to finish.');
      const before=structuredClone(this.state);
      try {
        const now=this.now(),packet=await pcEncrypt(this.state,contact,text,messageID,()=>this.call('/v1/keys/'+contact.id+'/claim','POST'),now);
        this.state.outbox.push(packet);
        this.state.messages.push({id:messageID,contactID:contact.id,text,outgoing:true,date:now,expiresAt:now+86400000,pending:true});this.persist();
      } catch(error) {this.state=before;throw error;}
    }
    try {await this.flush();}catch{return {ok:true,queued:true};}
    return {ok:true,queued:false};
  });}
  sync(session) {return this.work(session,async()=>{
    await this.flush();
    const inbox=await this.call('/v1/inbox'),ack=[];this.unverified=0;
    for(const packet of inbox.messages) {
      const marker=packet.sender+':'+packet.messageId;
      if(this.state.received.includes(marker)){ack.push(packet.seq);continue;}
      const contact=this.state.contacts[packet.sender];
      if(!contact||this.state.trusted[contact.id]!==contact.identityKey){this.unverified++;continue;}
      const before=structuredClone(this.state);
      try {
        const message=await pcDecrypt(this.state,packet);
        if(message.expiresAt>this.now()) {
          if(this.state.messages.length>=1000)throw new Error('PC inbox is full.');
          this.state.messages.push({id:packet.messageId,contactID:packet.sender,...message,outgoing:false,pending:false});
        }
        if(this.state.received.length>=20000)throw new Error('PC receipt capacity reached.');
        this.state.received.push(marker);this.persist();ack.push(packet.seq);
      } catch(error) {this.state=before;fail(409,'A message could not be decrypted. It remains queued; recheck the sender safety number.');}
    }
    if(ack.length)await this.call('/v1/inbox/ack','POST',{sequences:ack});
    const inventory=await this.call('/v1/device');
    if(inventory.identityKey!==pcPublication(this.state).identityKey)fail(409,'PC identity differs from its published key. Keep the original vault.');
    if(Math.min(inventory.preKeys,inventory.kyberPreKeys)<10){preparePCKeys(this.state,15);this.persist();await this.call('/v1/device','PUT',pcPublication(this.state));}
    return this.snapshot();
  },{touch:false});}
}
