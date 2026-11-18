// Storage for Encrypto: PostgreSQL when DATABASE_URL is set, otherwise memory only
// (memory-only data is lost whenever the server restarts).
// Only accounts, profile settings and not-yet-delivered ciphertext are stored.
// Message contents stay end-to-end encrypted; the database never sees plaintext.
const URL = process.env.DATABASE_URL;
let pool = null;
const memQueue = new Map();
const QUEUE_LIMIT = 300; // undelivered messages kept per recipient

async function init() {
  if (!URL) {
    console.log('No DATABASE_URL set: using in-memory storage. Accounts are lost on restart.');
    return [];
  }
  const { Pool } = require('pg');
  const local = /@(localhost|127\.0\.0\.1)[:/]/.test(URL);
  pool = new Pool({
    connectionString: URL,
    ssl: process.env.PGSSL === 'disable' || local ? false : { rejectUnauthorized: false },
    max: 5,
  });
  await pool.query(`create table if not exists users (
    email text primary key,
    name text not null,
    pubkey text not null,
    salt bytea,
    hash bytea,
    about text not null default '',
    pic text not null default '',
    priv jsonb not null,
    blocks text[] not null default '{}',
    contacts text[] not null default '{}',
    last_seen bigint,
    created_at timestamptz not null default now()
  )`);
  await pool.query(`create table if not exists queue (
    id bigserial primary key,
    to_email text not null,
    msg jsonb not null,
    created_at timestamptz not null default now()
  )`);
  await pool.query('create index if not exists queue_to on queue (to_email)');
  await pool.query("delete from queue where created_at < now() - interval '30 days'");
  const { rows } = await pool.query('select * from users');
  console.log(`PostgreSQL connected: ${rows.length} account(s) loaded.`);
  return rows.map((r) => ({
    email: r.email, name: r.name, key: r.pubkey, salt: r.salt, hash: r.hash,
    about: r.about, pic: r.pic, priv: r.priv, blocks: r.blocks, contacts: r.contacts,
    lastSeen: r.last_seen == null ? null : Number(r.last_seen),
  }));
}

async function saveUser(u) {
  if (!pool) return;
  await pool.query(
    `insert into users (email, name, pubkey, salt, hash, about, pic, priv, blocks, contacts, last_seen)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     on conflict (email) do update set name=$2, pubkey=$3, salt=$4, hash=$5, about=$6, pic=$7,
       priv=$8, blocks=$9, contacts=$10, last_seen=$11`,
    [u.email, u.name, u.key, u.salt, u.hash, u.about, u.pic, JSON.stringify(u.priv),
      [...u.blocks], [...u.contacts], u.lastSeen]);
}

async function enqueue(to, msg) {
  if (!pool) {
    const q = memQueue.get(to) || [];
    if (q.length < QUEUE_LIMIT) q.push(msg);
    memQueue.set(to, q);
    return;
  }
  await pool.query('insert into queue (to_email, msg) values ($1, $2)', [to, JSON.stringify(msg)]);
  await pool.query(
    'delete from queue where to_email = $1 and id not in (select id from queue where to_email = $1 order by id desc limit $2)',
    [to, QUEUE_LIMIT]);
}

async function takeQueue(to) {
  if (!pool) { const q = memQueue.get(to) || []; memQueue.delete(to); return q; }
  const { rows } = await pool.query('delete from queue where to_email = $1 returning id, msg', [to]);
  return rows.sort((a, b) => Number(a.id) - Number(b.id)).map((r) => r.msg);
}

module.exports = { init, saveUser, enqueue, takeQueue };