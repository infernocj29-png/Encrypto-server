// Encrypto relay server. Passwords are hashed with scrypt; messages stay ciphertext.
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
const fs = require('fs');
const path = require('path');
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
const wss = new WebSocketServer({ server, maxPayload: 1024 * 1024 });

const users = new Map(); // email -> { name, key, salt, hash, ws }
const queue = new Map(); // email -> [message] held until the recipient connects
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const TOKENINFO = process.env.GOOGLE_TOKENINFO_URL || 'https://oauth2.googleapis.com/tokeninfo';
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));
const broadcast = (obj, except) => wss.clients.forEach((c) => c !== except && c.authed && send(c, obj));

wss.on('connection', (ws) => {
  let me = null;

  // Mark this socket as signed in, announce presence and flush queued messages.
  const accept = (email, u) => {
    me = email;
    ws.authed = true;
    send(ws, { type: 'ready', username: email, name: u.name });
    send(ws, { type: 'presence', list: [...users].filter(([, x]) => x.ws && x.ws.readyState === 1).map(([e]) => e) });
    broadcast({ type: 'presence', email, online: true }, ws);
    for (const msg of queue.get(email) || []) send(ws, msg);
    queue.delete(email);
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
        u = { name, key, salt, hash: await scrypt(pw, salt), ws };
        users.set(email, u);
      } else {
        if (!u) return fail('No account found for that email.');
        if (!u.hash) return fail('This account uses Google sign-in. Please use the Google button.');
        if (!crypto.timingSafeEqual(await scrypt(pw, u.salt), u.hash)) return fail('Incorrect password. Please try again.');
        if (u.key !== key) return fail('This device does not hold the keys for that account.');
        u.ws = ws;
      }
      return accept(email, u);
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
        u = { name: String(info.name || email.split('@')[0]).slice(0, 60), key, salt: null, hash: null, ws };
        users.set(email, u);
      } else {
        if (u.key !== key) return fail('This device does not hold the keys for that account.');
        u.ws = ws;
      }
      return accept(email, u);
    }

    if (!me) return;

    if (m.type === 'typing') {
      const t = users.get(String(m.to || '').toLowerCase());
      if (t && t.ws) send(t.ws, { type: 'typing', from: me });
      return;
    }

    if (m.type === 'lookup') {
      const u = users.get(String(m.username || '').toLowerCase());
      return send(ws, { type: 'key', id: m.id, username: m.username,
        publicKey: u ? JSON.parse(u.key) : null, name: u ? u.name : null,
        online: !!(u && u.ws && u.ws.readyState === 1) });
    }

    if (m.type === 'msg') {
      const to = String(m.to || '').toLowerCase();
      const target = users.get(to);
      if (!target) return fail(`No account found for ${to}.`);
      const out = { type: 'msg', from: me, iv: m.iv, ct: m.ct, ts: Date.now() };
      if (target.ws && target.ws.readyState === 1) send(target.ws, out);
      else queue.set(to, [...(queue.get(to) || []), out]);
    }
  });

  ws.on('close', () => {
    const u = me && users.get(me);
    if (u && u.ws === ws) { u.ws = null; broadcast({ type: 'presence', email: me, online: false }); }
  });
});

// Keep idle WebSocket connections alive through Render's proxy.
setInterval(() => wss.clients.forEach((c) => c.readyState === 1 && c.ping()), 30000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Encrypto running on http://localhost:${PORT}`));
