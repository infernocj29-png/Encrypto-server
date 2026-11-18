// Encrypto relay server. Passwords are hashed with scrypt; messages stay ciphertext.
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const db = require('./db');

const app = express();
// Serve the app from ./public, or from index.html next to server.js if that is where it was uploaded.
const PUBLIC_DIR = path.join(__dirname, 'public');
const INDEX_FILE = [path.join(PUBLIC_DIR, 'index.html'), path.join(__dirname, 'index.html')].find(fs.existsSync);
app.use(express.static(PUBLIC_DIR));
app.get('/', (req, res) => INDEX_FILE
  ? res.sendFile(INDEX_FILE)
  : res.status(404).send('index.html not found. Put it in a folder named "public" next to server.js.'));
app.get('/healthz', (req, res) => res.send('ok'));
// Public config for the browser: only the Google Client ID (not a secret).
app.get('/config.json', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.json({ googleClientId: GOOGLE_CLIENT_ID });
});
const server = http.createServer(app);
const wss = new WebSocketServer({ server, maxPayload: 2 * 1024 * 1024 });

// email -> { email, name, key, salt, hash, ws, about, pic, priv, blocks, contacts, lastSeen }
const users = new Map();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const TOKENINFO = process.env.GOOGLE_TOKENINFO_URL || 'https://oauth2.googleapis.com/tokeninfo';
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LEVELS = ['everyone', 'contacts', 'nobody'];
const FIELDS = ['photo', 'about', 'lastSeen', 'online'];
const PIC = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/;

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
const persist = (u) => db.saveUser(u).catch((e) => console.error('Could not save user', u.email, e.message));
const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));
const isOn = (u) => !!(u.ws && u.ws.readyState === 1);
const newUser = (email, f) => ({
  email, about: '', pic: '', ws: null, lastSeen: null, salt: null, hash: null,
  priv: { photo: 'everyone', about: 'everyone', lastSeen: 'everyone', online: 'everyone' },
  blocks: new Set(), contacts: new Set(), ...f,
});
// Can `viewer` see `u`'s field, according to u's privacy choice?
const canSee = (u, viewer, field) => {
  if (viewer === u.email) return true;
  const l = u.priv[field];
  return l === 'everyone' || (l === 'contacts' && u.contacts.has(viewer));
};
const profileOf = (u, viewer) => ({
  email: u.email, name: u.name,
  about: canSee(u, viewer, 'about') ? u.about : '',
  pic: canSee(u, viewer, 'photo') ? u.pic : '',
});
const presenceFor = (u, viewer) => {
  const on = isOn(u) && canSee(u, viewer, 'online');
  return { type: 'presence', email: u.email, online: on,
    lastSeen: !on && canSee(u, viewer, 'lastSeen') ? u.lastSeen : null };
};
const eachAuthed = (u, fn) => wss.clients.forEach((c) => c.authed && c.email !== u.email && fn(c));
const announcePresence = (u) => eachAuthed(u, (c) => send(c, presenceFor(u, c.email)));
const pushProfile = (u) => eachAuthed(u, (c) => u.contacts.has(c.email) && send(c, { type: 'profile', ...profileOf(u, c.email) }));

wss.on('connection', (ws) => {
  let me = null; // the signed-in user object

  // Mark this socket as signed in, announce presence and flush queued messages.
  const accept = async (u) => {
    me = u; ws.authed = true; ws.email = u.email;
    send(ws, { type: 'ready', username: u.email, name: u.name, hasPassword: !!u.hash, about: u.about, pic: u.pic, privacy: u.priv });
    send(ws, { type: 'presence', list: [...users.values()].filter((x) => x.email !== u.email && isOn(x) && canSee(x, u.email, 'online')).map((x) => x.email) });
    announcePresence(u);
    for (const msg of await db.takeQueue(u.email)) {
      send(ws, msg);
      const sender = users.get(msg.from);
      if (msg.mid && sender && isOn(sender)) send(sender.ws, { type: 'ack', mid: msg.mid, status: 'delivered' });
    }
  };

  ws.on('message', async (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }
    const fail = (error) => send(ws, { type: 'error', error });

    if (m.type === 'signup' || m.type === 'login') {
      const email = String(m.email || '').trim().toLowerCase();
      const pw = String(m.password || '');
      if (!EMAIL.test(email) || email.length > 120) return fail('Enter a valid email address.');
      const key = JSON.stringify(m.publicKey);
      let u = users.get(email);

      if (m.type === 'signup') {
        const name = String(m.name || '').trim().slice(0, 60);
        if (!name) return fail('Please enter your full name.');
        if (pw.length < 8 || pw.length > 200) return fail('Use at least 8 characters for your password.');
        if (u) return fail('An account with this email already exists. Try logging in.');
        const salt = crypto.randomBytes(16);
        u = newUser(email, { name, key, salt, hash: await scrypt(pw, salt), ws });
        try { await db.saveUser(u); } catch (e) { console.error(e.message); return fail('Could not create your account right now. Please try again.'); }
        users.set(email, u);
      } else {
        if (!u) return fail('No account found for that email.');
        if (!u.hash) return fail('This account uses Google sign-in. Please use the Google button.');
        if (!crypto.timingSafeEqual(await scrypt(pw, u.salt), u.hash)) return fail('Incorrect password. Please try again.');
        if (u.key !== key) return fail('This device does not hold the keys for that account.');
        u.ws = ws;
      }
      return accept(u);
    }

    if (m.type === 'google') {
      if (!GOOGLE_CLIENT_ID) return fail('Google sign-in is not configured on this server.');
      let info;
      try {
        const r = await fetch(TOKENINFO + '?id_token=' + encodeURIComponent(String(m.credential || '')));
        if (!r.ok) throw new Error('bad token');
        info = await r.json();
      } catch { return fail('Google could not verify your sign-in. Please try again.'); }
      const issuerOk = ['accounts.google.com', 'https://accounts.google.com'].includes(info.iss);
      if (info.aud !== GOOGLE_CLIENT_ID || !issuerOk || String(info.email_verified) !== 'true' || !info.email) {
        return fail('Google sign-in could not be verified.');
      }
      const email = String(info.email).toLowerCase();
      const key = JSON.stringify(m.publicKey);
      let u = users.get(email);
      if (!u) {
        u = newUser(email, { name: String(info.name || email.split('@')[0]).slice(0, 60), key, ws });
        try { await db.saveUser(u); } catch (e) { console.error(e.message); return fail('Could not create your account right now. Please try again.'); }
        users.set(email, u);
      } else {
        if (u.key !== key) return fail('This device does not hold the keys for that account.');
        u.ws = ws;
      }
      return accept(u);
    }

    if (!me) return;

    if (m.type === 'profile') {
      const name = String(m.name || '').trim().slice(0, 60);
      const about = String(m.about || '').slice(0, 140);
      const pic = String(m.pic || '');
      if (!name) return fail('Your name cannot be empty.');
      if (pic && (pic.length > 200000 || !PIC.test(pic))) return fail('That profile picture is not supported.');
      Object.assign(me, { name, about, pic });
      persist(me);
      send(ws, { type: 'profile', ...profileOf(me, me.email) });
      return pushProfile(me);
    }

    if (m.type === 'privacy') {
      for (const f of FIELDS) if (LEVELS.includes(m.privacy && m.privacy[f])) me.priv[f] = m.privacy[f];
      persist(me); announcePresence(me); pushProfile(me);
      return;
    }

    if (m.type === 'block') {
      const e = String(m.email || '').toLowerCase();
      m.on ? me.blocks.add(e) : me.blocks.delete(e);
      persist(me);
      return;
    }

    if (m.type === 'password') {
      if (!me.hash) return fail('This account uses Google sign-in and has no password.');
      const next = String(m.next || '');
      if (next.length < 8 || next.length > 200) return fail('Use at least 8 characters for your new password.');
      if (!crypto.timingSafeEqual(await scrypt(String(m.current || ''), me.salt), me.hash)) return fail('Your current password is incorrect.');
      me.salt = crypto.randomBytes(16); me.hash = await scrypt(next, me.salt);
      persist(me);
      return send(ws, { type: 'password_ok' });
    }

    if (m.type === 'typing') {
      const t = users.get(String(m.to || '').toLowerCase());
      if (t && isOn(t) && !t.blocks.has(me.email)) send(t.ws, { type: 'typing', from: me.email });
      return;
    }

    if (m.type === 'lookup') {
      const t = users.get(String(m.username || '').toLowerCase());
      if (!t) return send(ws, { type: 'key', id: m.id, username: m.username, publicKey: null });
      const p = profileOf(t, me.email), pr = presenceFor(t, me.email);
      return send(ws, { type: 'key', id: m.id, username: m.username, publicKey: JSON.parse(t.key),
        name: p.name, about: p.about, pic: p.pic, online: pr.online, lastSeen: pr.lastSeen });
    }

    if (m.type === 'msg') {
      const to = String(m.to || '').toLowerCase();
      const target = users.get(to);
      if (!target) return fail(`No account found for ${to}.`);
      const mid = typeof m.mid === 'string' ? m.mid.slice(0, 64) : null;
      if (target.blocks.has(me.email)) return mid && send(ws, { type: 'ack', mid, status: 'sent' }); // dropped silently
      if (!me.contacts.has(to) || !target.contacts.has(me.email)) { me.contacts.add(to); target.contacts.add(me.email); persist(me); persist(target); }
      const out = { type: 'msg', from: me.email, iv: m.iv, ct: m.ct, ts: Date.now(), mid };
      if (isOn(target)) {
        send(target.ws, out);
        if (mid) send(ws, { type: 'ack', mid, status: 'delivered' });
      } else {
        try { await db.enqueue(to, out); } catch (e) { console.error('Could not queue message', e.message); return fail('Message could not be saved for delivery. Please try again.'); }
        if (mid) send(ws, { type: 'ack', mid, status: 'sent' });
      }
    }
  });

  ws.on('close', () => {
    if (me && me.ws === ws) { me.ws = null; me.lastSeen = Date.now(); persist(me); announcePresence(me); }
  });
});

// Keep idle WebSocket connections alive through Render's proxy.
setInterval(() => wss.clients.forEach((c) => c.readyState === 1 && c.ping()), 30000);

process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));

const PORT = process.env.PORT || 3000;
db.init().then((rows) => {
  for (const r of rows) users.set(r.email, newUser(r.email, { ...r, blocks: new Set(r.blocks), contacts: new Set(r.contacts) }));
  server.listen(PORT, () => console.log(`Encrypto running on http://localhost:${PORT}`));
}).catch((e) => { console.error('Could not start the database:', e.message); process.exit(1); });
