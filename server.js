// Encrypto relay server. Passwords are hashed with scrypt; messages stay ciphertext.
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
app.use(express.static(require('path').join(__dirname, 'public')));
app.get('/healthz', (req, res) => res.send('ok'));
const server = http.createServer(app);
const wss = new WebSocketServer({ server, maxPayload: 1024 * 1024 });

const users = new Map(); // email -> { name, key, salt, hash, ws }
const queue = new Map(); // email -> [message] held until the recipient connects
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));
const broadcast = (obj, except) => wss.clients.forEach((c) => c !== except && c.authed && send(c, obj));

wss.on('connection', (ws) => {
  let me = null;

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
        if (!crypto.timingSafeEqual(await scrypt(pw, u.salt), u.hash)) return fail('Incorrect password. Please try again.');
        if (u.key !== key) return fail('This device does not hold the keys for that account.');
        u.ws = ws;
      }
      me = email;
      ws.authed = true;
      send(ws, { type: 'ready', username: email, name: u.name });
      send(ws, { type: 'presence', list: [...users].filter(([, x]) => x.ws && x.ws.readyState === 1).map(([e]) => e) });
      broadcast({ type: 'presence', email, online: true }, ws);
      for (const msg of queue.get(email) || []) send(ws, msg);
      queue.delete(email);
      return;
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
