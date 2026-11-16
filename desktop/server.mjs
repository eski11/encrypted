// SPDX-License-Identifier: AGPL-3.0-only
import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, createHash, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { Discovery } from './discovery.mjs';
import { SecureTransport } from './transport.mjs';
import { AccountSecurity } from './account-security.mjs';
import { PCChat } from './pc-chat.mjs';

const derive = promisify(scrypt);
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const username = value => {
  if (typeof value !== 'string' || !/^[a-z0-9_]{3,32}$/.test(value)) fail(400, 'Use a username of 3–32 lowercase letters, digits or underscores.');
  return value;
};
const id = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f-]{27}$/.test(value)) fail(400, 'Invalid identifier.');
  return value;
};
function bytes(value, min, max) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) fail(400, 'Invalid encoded bytes.');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value || decoded.length < min || decoded.length > max) fail(400, 'Invalid encoded byte length.');
  return decoded;
}
function integer(value, max = 0xffffffff) {
  if (!Number.isInteger(value) || value < 1 || value > max) fail(400, 'Invalid key identifier.');
  return value;
}
function object(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.includes(k))) fail(400, 'Unexpected request fields.');
}
async function body(req, maximum = 256 * 1024) {
  if (!req.headers['content-type']?.startsWith('application/json')) fail(415, 'Use application/json.');
  const chunks = []; let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > maximum) fail(413, 'Request too large.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { fail(400, 'Invalid JSON.'); }
}
function reply(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(value));
}

export function createRelay({ directory, adminToken, adminPage = '', getPublicURL = () => null, automaticConnection = () => false, onShutdown = () => {}, allowLegacy = false, now = () => Date.now() }) {
  mkdirSync(directory, { recursive: true });
  const db = new DatabaseSync(join(directory, 'encptd.sqlite'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, verifier BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS devices(user_id TEXT PRIMARY KEY REFERENCES users(id), identity TEXT NOT NULL, registration INTEGER NOT NULL, signed_key TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS prekeys(user_id TEXT NOT NULL, kind TEXT NOT NULL, key_id INTEGER NOT NULL, data TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,kind,key_id));
    CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL REFERENCES users(id), recipient TEXT NOT NULL REFERENCES users(id), message_id TEXT NOT NULL, kind INTEGER NOT NULL, ciphertext BLOB NOT NULL, created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS dedup(sender TEXT NOT NULL, message_id TEXT NOT NULL, recipient TEXT NOT NULL, digest TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(sender,message_id));
    CREATE INDEX IF NOT EXISTS inbox ON messages(recipient,seq);
    CREATE TABLE IF NOT EXISTS transport_replays(request_id TEXT PRIMARY KEY, expires INTEGER NOT NULL);`);
  const transport = new SecureTransport(directory, new Discovery(directory).state.instanceID);
  const accountSecurity = new AccountSecurity(db, { now, verifyPassword: async (userID,password) => {
    if(typeof password!=='string'||password.length>256) fail(400,'Enter your account password.');
    rate(`security-settings:${userID}`,8,3600000);
    if(activeLogins>=4) fail(503,'Server is busy.');
    activeLogins++;
    try {
      const user=db.prepare('SELECT salt,verifier FROM users WHERE id=?').get(userID);
      if(!user) fail(410,'This account was deleted.');
      const candidate=await derive(password,user.salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});
      if(!timingSafeEqual(candidate,user.verifier)) fail(403,'Account password is incorrect.');
    } finally { activeLogins--; }
  } });
  const cleanup = () => {
    accountSecurity.cleanup();
    db.prepare('DELETE FROM messages WHERE created<?').run(now() - 7 * 86400000);
    db.prepare('DELETE FROM dedup WHERE created<?').run(now() - 30 * 86400000);
    db.prepare('DELETE FROM sessions WHERE expires<=?').run(now());
    db.prepare('DELETE FROM transport_replays WHERE expires<=?').run(now());
  };
  cleanup();
  const maintenance = setInterval(cleanup,60000); maintenance.unref();
  const limits = new Map(); let activeLogins = 0, activeTransports = 0;
  const rate = (key, max, windowMs) => {
    const now = Date.now(); let bucket = limits.get(key);
    if (!bucket || bucket.until < now) bucket = { count: 0, until: now + windowMs };
    if (++bucket.count > max) fail(429, 'Too many requests. Try again later.');
    limits.set(key, bucket);
    if (limits.size > 10000) for (const [k, v] of limits) if (v.until < now) limits.delete(k);
    if (limits.size > 20000) fail(503, 'Server is busy.');
  };
  const auth = req => {
    const token = req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1];
    if (!token) fail(401, 'Sign in required.');
    const row = db.prepare('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.expires>?').get(digest(token), Date.now());
    if (!row) fail(401, 'Session expired. Sign in again.');
    rate(`user:${row.id}`, 360, 60000);
    return row;
  };
  function transaction(fn) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  function issueSession(user) {
    const token = randomBytes(32).toString('base64url');
    db.prepare('DELETE FROM sessions WHERE expires<=?').run(Date.now());
    db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest(token), user.id, Date.now() + 30 * 86400000);
    return { id: user.id, username: user.username, token };
  }
  async function createAccount(input, withSession = false) {
    object(input, ['username', 'password']); username(input.username);
    if (typeof input.password !== 'string' || input.password.length < 12 || input.password.length > 256) fail(400, 'Use a password of 12–256 characters.');
    const available = () => {
      if (db.prepare('SELECT count(*) AS count FROM users').get().count >= 100) fail(409, 'Account limit reached.');
      if (db.prepare('SELECT 1 FROM users WHERE username=?').get(input.username)) fail(409, 'Username already exists. Sign in or choose another name.');
    };
    available();
    if (activeLogins >= 4) fail(503, 'Server is busy. Try again shortly.');
    activeLogins++;
    try {
      const salt = randomBytes(16), user = { id: randomUUID(), username: input.username };
      const key = await derive(input.password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
      return transaction(() => {
        available(); // Recheck after the asynchronous KDF, inside the write transaction.
        db.prepare('INSERT INTO users VALUES(?,?,?,?)').run(user.id, user.username, salt, key);
        return withSession ? issueSession(user) : user;
      });
    } finally { activeLogins--; }
  }
  async function client(req, res) {
    const url = new URL(req.url, 'http://localhost');
    if (url.search) fail(400, 'Query parameters are not supported.');
    const path = url.pathname;
    if (req.method === 'GET' && path === '/v1/health') return reply(res, 200, { service: 'ENCPTD', version: 1, release: '0.5.0', protectedTransport: true });
    accountSecurity.cleanup();
    const publicSecurity={ '/v1/security/confirm':'confirm','/v1/security/challenge':'challenge','/v1/security/unlock':'unlock','/v1/security/destroy':'destroy' }[path];
    if(req.method==='POST'&&publicSecurity) {
      rate('security-public',120,60000);
      return reply(res,200,accountSecurity[publicSecurity](await body(req)));
    }
    if (path === '/v1/inbox' || path === '/v1/messages') cleanup();
    if (req.method === 'POST' && path === '/v1/register') {
      // All requests arrive through a local tunnel: deliberately use a global limit,
      // rather than trusting attacker-controlled forwarded IP headers.
      rate('registration', 12, 3600000);
      return reply(res, 201, await createAccount(await body(req), true));
    }
    if (req.method === 'POST' && path === '/v1/login') {
      const input = await body(req); object(input, ['username', 'password']);
      const name = username(input.username);
      if (typeof input.password !== 'string' || input.password.length > 256) fail(400, 'Invalid password.');
      rate(`login:${name}`, 15, 15 * 60000);
      if (activeLogins >= 4) fail(503, 'Please try signing in again shortly.');
      activeLogins++;
      try {
        const user = db.prepare('SELECT * FROM users WHERE username=?').get(name);
        const key = await derive(input.password, user?.salt ?? Buffer.alloc(16), 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
        if (!user || !timingSafeEqual(key, user.verifier)) fail(401, 'Username or password is incorrect.');
        return reply(res, 200, issueSession(user));
      } finally { activeLogins--; }
    }
    const me = auth(req);
    if(req.method==='GET'&&path==='/v1/security') return reply(res,200,accountSecurity.policy(me.id));
    if(req.method==='POST'&&path==='/v1/security/prepare') return reply(res,200,await accountSecurity.prepare(me.id,await body(req)));
    if (req.method === 'POST' && path === '/v1/password') {
      rate(`password:${me.id}`,5,3600000);
      const input=await body(req); object(input,['oldPassword','newPassword']);
      if (typeof input.oldPassword !== 'string' || input.oldPassword.length > 256 || typeof input.newPassword !== 'string' || input.newPassword.length < 12 || input.newPassword.length > 256) fail(400,'Use a new password of 12–256 characters.');
      if (input.newPassword === input.oldPassword) fail(400,'Choose a different password.');
      if (activeLogins >= 4) fail(503,'Server is busy. Try again shortly.');
      activeLogins++;
      try {
        const user=db.prepare('SELECT * FROM users WHERE id=?').get(me.id);
        const oldKey=await derive(input.oldPassword,user.salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});
        if (!timingSafeEqual(oldKey,user.verifier)) fail(403,'Current password is incorrect.');
        const salt=randomBytes(16),key=await derive(input.newPassword,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});
        const result=transaction(()=>{
          const changed=db.prepare('UPDATE users SET salt=?,verifier=? WHERE id=? AND verifier=?').run(salt,key,me.id,user.verifier);
          if (!changed.changes) fail(409,'Password changed during this request. Sign in again.');
          db.prepare('DELETE FROM sessions WHERE user_id=?').run(me.id);
          return issueSession(me);
        });
        return reply(res,200,result);
      } finally { activeLogins--; }
    }
    if (req.method === 'POST' && path === '/v1/logout') {
      db.prepare('DELETE FROM sessions WHERE hash=?').run(digest(req.headers.authorization.slice(7)));
      return reply(res, 200, { ok: true });
    }
    if (req.method === 'GET' && path === '/v1/device') {
      const device = db.prepare('SELECT identity,registration FROM devices WHERE user_id=?').get(me.id);
      const available = db.prepare('SELECT count(*) AS count FROM prekeys WHERE user_id=? AND kind=? AND used=0');
      return reply(res, 200, { identityKey: device?.identity ?? null, preKeys: available.get(me.id, 'ec').count, kyberPreKeys: available.get(me.id, 'kyber').count });
    }
    if (req.method === 'PUT' && path === '/v1/device') {
      const input = await body(req); object(input, ['identityKey', 'registrationId', 'signedPreKey', 'preKeys', 'kyberPreKeys']);
      bytes(input.identityKey, 33, 33); integer(input.registrationId, 16383);
      const validateKey = (key, kyber = false, signed = false) => {
        object(key, signed || kyber ? ['id', 'key', 'signature'] : ['id', 'key']);
        integer(key.id); bytes(key.key, kyber ? 1000 : 33, kyber ? 2000 : 33);
        if (signed || kyber) bytes(key.signature, 64, 64);
      };
      validateKey(input.signedPreKey, false, true);
      for (const [keyName, kyber] of [['preKeys', false], ['kyberPreKeys', true]]) {
        if (!Array.isArray(input[keyName]) || input[keyName].length > 100) fail(400, 'Invalid public key pool.');
        input[keyName].forEach(k => validateKey(k, kyber));
      }
      transaction(() => {
        const old = db.prepare('SELECT * FROM devices WHERE user_id=?').get(me.id);
        if (old && (old.identity !== input.identityKey || old.registration !== input.registrationId)) fail(409, 'This account is already paired to another installation. Contact your server owner.');
        db.prepare('INSERT INTO devices VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET signed_key=excluded.signed_key').run(me.id, input.identityKey, input.registrationId, JSON.stringify(input.signedPreKey));
        const insert = db.prepare('INSERT OR IGNORE INTO prekeys(user_id,kind,key_id,data) VALUES(?,?,?,?)');
        const count = db.prepare('SELECT count(*) AS count FROM prekeys WHERE user_id=?').get(me.id).count;
        if (count > 10000) fail(409, 'Public key storage limit reached.');
        for (const key of input.preKeys) insert.run(me.id, 'ec', key.id, JSON.stringify(key));
        for (const key of input.kyberPreKeys) insert.run(me.id, 'kyber', key.id, JSON.stringify(key));
      });
      return reply(res, 200, { ok: true });
    }
    const lookup = path.match(/^\/v1\/users\/([a-z0-9_]{3,32})$/);
    if (req.method === 'GET' && lookup) {
      const row = db.prepare('SELECT u.id,u.username,d.identity AS identityKey FROM users u JOIN devices d ON d.user_id=u.id WHERE u.username=?').get(lookup[1]);
      if (!row) fail(404, 'That person has not set up their phone yet.');
      return reply(res, 200, row);
    }
    const claim = path.match(/^\/v1\/keys\/([0-9a-f-]+)\/claim$/);
    if (req.method === 'POST' && claim) {
      const target = id(claim[1]); rate(`claim:${me.id}:${target}`, 15, 3600000);
      const bundle = transaction(() => {
        const device = db.prepare('SELECT * FROM devices WHERE user_id=?').get(target);
        if (!device) fail(404, 'Recipient is not ready.');
        const select = db.prepare('SELECT key_id,data FROM prekeys WHERE user_id=? AND kind=? AND used=0 ORDER BY key_id LIMIT 1');
        const ec = select.get(target, 'ec'), kyber = select.get(target, 'kyber');
        if (!ec || !kyber) fail(409, 'Recipient needs to open ENCPTD to refresh their public keys.');
        const consume = db.prepare('UPDATE prekeys SET used=1 WHERE user_id=? AND kind=? AND key_id=?');
        consume.run(target, 'ec', ec.key_id); consume.run(target, 'kyber', kyber.key_id);
        return { identityKey: device.identity, registrationId: device.registration, signedPreKey: JSON.parse(device.signed_key), preKey: JSON.parse(ec.data), kyberPreKey: JSON.parse(kyber.data) };
      });
      return reply(res, 200, bundle);
    }
    if (req.method === 'POST' && path === '/v1/messages') {
      rate(`send:${me.id}`, 120, 60000);
      const input = await body(req); object(input, ['messageId', 'recipient', 'kind', 'ciphertext']);
      id(input.messageId); id(input.recipient);
      if (![2, 3].includes(input.kind)) fail(400, 'Only encrypted Signal message types are accepted.');
      const ciphertext = bytes(input.ciphertext, 16, 128 * 1024);
      const hash = digest(Buffer.concat([Buffer.from(`${input.kind}:${input.recipient}:`),ciphertext]));
      transaction(() => {
        const prior = db.prepare('SELECT * FROM dedup WHERE sender=? AND message_id=?').get(me.id, input.messageId);
        if (prior) {
          const matches = prior.recipient ? prior.digest === digest(ciphertext) && prior.recipient === input.recipient : prior.digest === hash;
          if (!matches) fail(409, 'Message identifier conflict.');
          return;
        }
        if (!db.prepare('SELECT 1 FROM devices WHERE user_id=?').get(input.recipient)) fail(404, 'Recipient is not ready.');
        if (!db.prepare('SELECT 1 FROM devices WHERE user_id=?').get(me.id)) fail(409, 'Set up your phone encryption keys first.');
        if (db.prepare('SELECT count(*) AS count FROM messages WHERE recipient=?').get(input.recipient).count >= 1000) fail(429, 'Recipient inbox is full.');
        if (db.prepare('SELECT coalesce(sum(length(ciphertext)),0) AS bytes FROM messages').get().bytes + ciphertext.length > 100 * 1024 * 1024) fail(507, 'Server message storage is full.');
        const created = Math.floor(now()/60000)*60000;
        db.prepare('INSERT INTO messages(sender,recipient,message_id,kind,ciphertext,created) VALUES(?,?,?,?,?,?)').run(me.id, input.recipient, input.messageId, input.kind, ciphertext, created);
        db.prepare('INSERT INTO dedup VALUES(?,?,?,?,?)').run(me.id, input.messageId, '', hash, created);
      });
      return reply(res, 200, { ok: true, messageId: input.messageId });
    }
    if (req.method === 'GET' && path === '/v1/inbox') {
      const messages = db.prepare('SELECT m.seq,m.sender,u.username AS senderUsername,m.message_id AS messageId,m.kind,m.ciphertext,m.created FROM messages m JOIN users u ON u.id=m.sender WHERE m.recipient=? ORDER BY m.seq LIMIT 10').all(me.id).map(m => ({ ...m, ciphertext: Buffer.from(m.ciphertext).toString('base64') }));
      return reply(res, 200, { messages });
    }
    if (req.method === 'POST' && path === '/v1/inbox/ack') {
      const input = await body(req); object(input, ['sequences']);
      if (!Array.isArray(input.sequences) || input.sequences.length > 100 || input.sequences.some(n => !Number.isSafeInteger(n) || n < 1)) fail(400, 'Invalid acknowledgement.');
      transaction(() => { const remove = db.prepare('DELETE FROM messages WHERE seq=? AND recipient=?'); for (const seq of input.sequences) remove.run(seq, me.id); });
      return reply(res, 200, { ok: true });
    }
    fail(404, 'Not found.');
  }
  const pcChat = new PCChat({ directory, now, accountExists: name=>!!db.prepare('SELECT 1 FROM users WHERE username=?').get(name), api:async(path,method='GET',input,token)=>{
    // An ordinary chat client local to this process; never an owner-token bypass.
    const req=Readable.from(input?[Buffer.from(JSON.stringify(input))]:[]);
    req.url=path;req.method=method;req.headers={'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})};
    let status,data;
    await client(req,{writeHead(code){status=code;},end(value){data=JSON.parse(value);}});
    if(status>=400)fail(status,data.error??'PC chat request failed.');
    return data;
  }});
  async function admin(req, res) {
    const host = req.headers.host;
    if (!/^(127\.0\.0\.1|localhost):\d+$/.test(host ?? '')) fail(403, 'Local administration only.');
    if (req.headers.origin && ![`http://${host}`].includes(req.headers.origin)) fail(403, 'Local administration only.');
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'" });
      return res.end(adminPage);
    }
    const supplied = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(supplied) || supplied.length !== adminToken.length || !timingSafeEqual(Buffer.from(supplied), Buffer.from(adminToken))) fail(401, 'Open the owner console using Start-ENCPTD.cmd.');
    if (req.method === 'GET' && req.url === '/connection') return reply(res, 200, { url: getPublicURL(), automatic: automaticConnection() });
    if (req.method === 'POST' && req.url === '/shutdown') { reply(res, 200, { ok: true }); setTimeout(onShutdown, 50); return; }
    if (req.method === 'POST' && req.url === '/revoke-sessions') {
      db.prepare('DELETE FROM sessions').run();
      return reply(res,200,{ok:true});
    }
    if (req.method === 'POST' && req.url === '/accounts') {
      return reply(res, 201, await createAccount(await body(req)));
    }
    if(req.method==='GET'&&req.url==='/accounts') {
      cleanup();
      const accounts=db.prepare(`SELECT u.id,u.username,EXISTS(SELECT 1 FROM devices d WHERE d.user_id=u.id) AS paired,
        (SELECT count(*) FROM sessions s WHERE s.user_id=u.id AND s.expires>?) AS sessions,
        (SELECT count(*) FROM messages m WHERE m.recipient=u.id) AS queued FROM users u ORDER BY u.username`).all(now());
      return reply(res,200,{accounts:accounts.map(a=>({...a,paired:!!a.paired}))});
    }
    const revoke=req.url.match(/^\/accounts\/([a-f0-9-]+)\/revoke-sessions$/);
    if(req.method==='POST'&&revoke) {
      const accountID=id(revoke[1]);
      if(!db.prepare('SELECT 1 FROM users WHERE id=?').get(accountID))fail(404,'Account not found.');
      const value=await body(req,1024);object(value,['confirmed']);if(value.confirmed!==true)fail(400,'Confirm signing out this account.');
      const result=db.prepare('DELETE FROM sessions WHERE user_id=?').run(accountID);
      return reply(res,200,{ok:true,revoked:result.changes});
    }
    if(req.method==='GET'&&req.url==='/pc-chat/status')return reply(res,200,await pcChat.status(req.headers['x-encptd-chat']));
    const action=req.method==='POST'&&req.url.match(/^\/pc-chat\/(setup|unlock|lock|contact|verify|send|sync)$/)?.[1];
    if(action) {
      const fields={setup:['username','passphrase'],unlock:['passphrase'],lock:[],contact:['username'],verify:['username','identityKey','compared'],send:['username','text','messageID'],sync:[]}[action];
      const input=await body(req,32*1024);object(input,fields);
      if(action==='setup'||action==='unlock') {
        rate('pc-chat-unlock',12,3600000);
        return reply(res,200,await pcChat[action](input));
      }
      if(action==='lock')return reply(res,200,await pcChat.lock());
      return reply(res,200,await pcChat[action](req.headers['x-encptd-chat'],input));
    }
    fail(404, 'Not found.');
  }
  const wrap = handler => async (req, res) => {
    try { rate(`ip:${req.socket.remoteAddress}`, 1200, 60000); await handler(req, res); }
    catch (error) {
      if (!res.headersSent) reply(res, error.status ?? 500, { error: error.status ? error.message : 'Server operation failed.' });
      else res.end();
    }
  };
  async function protectedClient(req,res) {
    if (req.method === 'GET' && req.url === '/v1/health') return client(req,res);
    if (allowLegacy && req.url !== '/v2/transport') return client(req,res);
    if (req.method !== 'POST' || req.url !== '/v2/transport') return reply(res,426,{error:'Update ENCPTD. An encrypted connection is required.'});
    if (activeTransports >= 8) fail(503,'Server is busy.');
    activeTransports++;
    try { return await encryptedClient(req,res); }
    finally { activeTransports--; }
  }
  async function encryptedClient(req,res) {
    let request;
    try { request = await transport.open(await body(req, 768 * 1024)); }
    catch { return reply(res,400,{error:'Invalid encrypted request.'}); }
    cleanup();
    if (db.prepare('SELECT count(*) AS count FROM transport_replays').get().count >= 10000) fail(503,'Server is busy.');
    const reserved = db.prepare('INSERT OR IGNORE INTO transport_replays VALUES(?,?)').run(request.input.requestID,now()+240000);
    if (!reserved.changes) return reply(res,409,{error:'Repeated encrypted request rejected.'});
    const inner = Readable.from(request.body.length ? [request.body] : []);
    inner.url = request.input.path; inner.method = request.input.method;
    inner.headers = { 'content-type':'application/json', ...(request.input.token ? {authorization:`Bearer ${request.input.token}`} : {}) };
    let status, responseBody;
    const response = { writeHead(code) { status=code; }, end(data) { responseBody=Buffer.from(data); } };
    try { await client(inner,response); }
    catch(error) { status=error.status??500; responseBody=Buffer.from(JSON.stringify({error:error.status?error.message:'Server operation failed.'})); }
    return reply(res,200,await request.seal(status,responseBody));
  }
  const clientServer = http.createServer({ requestTimeout: 15000, headersTimeout: 10000, maxHeaderSize: 8192 }, wrap(protectedClient));
  const adminServer = http.createServer({ requestTimeout: 15000, headersTimeout: 10000, maxHeaderSize: 8192 }, wrap(admin));
  return { clientServer, adminServer, db, close: () => { clearInterval(maintenance); pcChat.close(); db.close(); } };
}
