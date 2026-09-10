// Quick Dial signalling server.
//
// Relays call setup between two users. The audio itself is peer-to-peer and
// never passes through here.
//
// Accounts use an organisation ID of the form  name/number  (e.g. gaurav/16),
// are protected by a password, and start as "pending" until an admin approves.
//
// Passwords are never stored -- only a random salt and a scrypt hash.
//
// Storage: with DATABASE_URL set, accounts persist in Postgres. Without it they
// live in memory and are lost on restart, which is fine for testing only.

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// name, slash, number
const ID_FORMAT = /^[a-z][a-z.-]{1,19}\/[0-9]{1,10}$/;

/* ----------------------------------------------------------- account store */

const memory = new Map();          // id -> { salt, hash, status, created_at }
let pool = null;

async function initDb() {
  if (!process.env.DATABASE_URL) {
    console.log('No DATABASE_URL set - accounts are in memory only.');
    return;
  }
  const { Pool } = require('pg');
  const url = process.env.DATABASE_URL;
  // Render's internal hostnames (dpg-xxxx-a) speak plain TCP; external hosts
  // such as Neon or Render's external URL need SSL. Pick based on the host.
  const external = /sslmode=require/.test(url) || /@[^/]*\./.test(url);
  pool = new Pool({
    connectionString: url,
    ssl: external ? { rejectUnauthorized: false } : false
  });
  console.log('Database SSL: ' + (external ? 'on' : 'off'));
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id     TEXT PRIMARY KEY,
      salt   TEXT NOT NULL,
      hash   TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Older deployments may predate the status column.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'`);
  console.log('Accounts stored in Postgres.');
}

async function getUser(id) {
  if (!pool) return memory.get(id) || null;
  const r = await pool.query('SELECT salt, hash, status FROM users WHERE id = $1', [id]);
  return r.rows[0] || null;
}

async function putUser(id, salt, hash) {
  if (!pool) {
    memory.set(id, { salt, hash, status: 'pending', created_at: new Date() });
    return;
  }
  await pool.query(
    'INSERT INTO users (id, salt, hash, status) VALUES ($1, $2, $3, $4)',
    [id, salt, hash, 'pending']
  );
}

async function updateUser(id, salt, hash) {
  if (!pool) {
    if (!memory.has(id)) return false;
    memory.set(id, { ...memory.get(id), salt, hash });
    return true;
  }
  const r = await pool.query('UPDATE users SET salt = $2, hash = $3 WHERE id = $1', [id, salt, hash]);
  return r.rowCount > 0;
}

async function setStatus(id, status) {
  if (!pool) {
    if (!memory.has(id)) return false;
    memory.set(id, { ...memory.get(id), status });
    return true;
  }
  const r = await pool.query('UPDATE users SET status = $2 WHERE id = $1', [id, status]);
  return r.rowCount > 0;
}

async function deleteUser(id) {
  if (!pool) return memory.delete(id);
  const r = await pool.query('DELETE FROM users WHERE id = $1', [id]);
  return r.rowCount > 0;
}

async function listUsers() {
  if (!pool) {
    return [...memory.entries()].map(([id, u]) => ({
      id, status: u.status || 'pending', created_at: u.created_at || null
    }));
  }
  const r = await pool.query('SELECT id, status, created_at FROM users ORDER BY created_at DESC');
  return r.rows;
}

/* -------------------------------------------------------------- passwords */

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verify(password, user) {
  const a = Buffer.from(hashPassword(password, user.salt), 'hex');
  const b = Buffer.from(user.hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);      // constant time, resists guessing
}

/* ------------------------------------------------------------- rate limit */

const attempts = new Map();   // ip -> { count, until }

// Wrong passwords allowed per 15 minutes. Set LOGIN_ATTEMPT_LIMIT=0 to switch
// the lockout off entirely -- that also lets anyone guess passwords forever.
const ATTEMPT_LIMIT = process.env.LOGIN_ATTEMPT_LIMIT === undefined
  ? 25
  : Number(process.env.LOGIN_ATTEMPT_LIMIT);

function tooManyAttempts(ip) {
  if (!ATTEMPT_LIMIT) return false;
  const rec = attempts.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.until) { attempts.delete(ip); return false; }
  return rec.count >= ATTEMPT_LIMIT;
}

function noteFailure(ip) {
  if (!ATTEMPT_LIMIT) return;
  const rec = attempts.get(ip) || { count: 0, until: Date.now() + 15 * 60 * 1000 };
  rec.count += 1;
  attempts.set(ip, rec);
}

// A correct password clears the record, so normal typos never accumulate.
function clearAttempts(ip) { attempts.delete(ip); }

/* ---------------------------------------------------------------- sockets */

const online = new Map();     // id -> socket

function send(socket, payload) {
  if (socket && socket.readyState === 1) socket.send(JSON.stringify(payload));
}

function kick(id) {
  const sock = online.get(id);
  if (sock) { send(sock, { type: 'replaced' }); sock.close(); }
}

/* ------------------------------------------------------------ admin panel */

const ADMIN_KEY = process.env.ADMIN_KEY || '';

function adminOk(req) {
  if (!ADMIN_KEY) return false;
  const given = String(req.headers['x-admin-key'] || '');
  const a = Buffer.from(given);
  const b = Buffer.from(ADMIN_KEY);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function guard(req, res, next) {
  if (!ADMIN_KEY) return res.status(503).json({ error: 'Admin is disabled. Set ADMIN_KEY.' });
  if (!adminOk(req)) return res.status(401).json({ error: 'Wrong admin key' });
  next();
}

app.get('/api/admin/users', guard, async (req, res) => {
  try {
    const users = await listUsers();
    res.json({
      storage: pool ? 'postgres' : 'memory',
      users: users.map(u => ({ ...u, online: online.has(u.id) }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/status', guard, async (req, res) => {
  const id = String(req.body.id || '').trim().toLowerCase();
  const status = String(req.body.status || '');
  if (!['approved', 'pending', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Unknown status' });
  }
  try {
    const ok = await setStatus(id, status);
    if (!ok) return res.status(404).json({ error: 'No account with that ID' });
    if (status !== 'approved') kick(id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/password', guard, async (req, res) => {
  const id = String(req.body.id || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const salt = crypto.randomBytes(16).toString('hex');
    const ok = await updateUser(id, salt, hashPassword(password, salt));
    if (!ok) return res.status(404).json({ error: 'No account with that ID' });
    kick(id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/delete', guard, async (req, res) => {
  const id = String(req.body.id || '').trim().toLowerCase();
  try {
    const ok = await deleteUser(id);
    if (!ok) return res.status(404).json({ error: 'No account with that ID' });
    kick(id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------------------------------------------------------- ws signalling */

wss.on('connection', (socket, req) => {
  socket.userId = null;
  socket.isAlive = true;
  socket.ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  socket.on('pong', () => { socket.isAlive = true; });

  socket.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    if (msg.type === 'register') {
      const id = String(msg.id || '').trim().toLowerCase();
      const password = String(msg.password || '');

      if (!ID_FORMAT.test(id)) {
        return send(socket, { type: 'authfail', reason: 'ID must be name/number, like gaurav/16' });
      }
      if (password.length < 6) {
        return send(socket, { type: 'authfail', reason: 'Password must be at least 6 characters' });
      }
      if (tooManyAttempts(socket.ip)) {
        return send(socket, { type: 'authfail', reason: 'Too many wrong passwords. Try again in 15 minutes' });
      }

      let user;
      try { user = await getUser(id); }
      catch (e) { return send(socket, { type: 'authfail', reason: 'Server error, try again' }); }

      if (!user) {
        if (msg.mode === 'signin') {
          noteFailure(socket.ip);
          return send(socket, { type: 'authfail', reason: 'No account with that ID' });
        }
        const salt = crypto.randomBytes(16).toString('hex');
        try { await putUser(id, salt, hashPassword(password, salt)); }
        catch (e) { return send(socket, { type: 'authfail', reason: 'That ID was just taken' }); }
        clearAttempts(socket.ip);
        return send(socket, {
          type: 'pending',
          reason: 'Request sent. An admin has to approve it before you can sign in.'
        });
      }

      if (msg.mode === 'signup') {
        return send(socket, { type: 'authfail', reason: 'That ID is already registered' });
      }
      if (!verify(password, user)) {
        noteFailure(socket.ip);
        return send(socket, { type: 'authfail', reason: 'Wrong password' });
      }

      clearAttempts(socket.ip);

      const status = user.status || 'pending';
      if (status === 'pending') {
        return send(socket, { type: 'pending', reason: 'Your account is waiting for admin approval.' });
      }
      if (status !== 'approved') {
        return send(socket, { type: 'authfail', reason: 'This account was declined' });
      }

      const existing = online.get(id);
      if (existing && existing !== socket) {
        send(existing, { type: 'replaced' });
        existing.close();
      }
      socket.userId = id;
      online.set(id, socket);
      return send(socket, { type: 'registered', id });
    }

    if (!socket.userId) return send(socket, { type: 'authfail', reason: 'Sign in first' });

    const to = String(msg.to || '').trim().toLowerCase();
    const target = online.get(to);
    if (!target) return send(socket, { type: 'unreachable', to });

    send(target, { ...msg, from: socket.userId });
  });

  socket.on('close', () => {
    if (socket.userId && online.get(socket.userId) === socket) online.delete(socket.userId);
  });
});

setInterval(() => {
  wss.clients.forEach((s) => {
    if (s.isAlive === false) return s.terminate();
    s.isAlive = false;
    s.ping();
  });
}, 30000);

const PORT = process.env.PORT || 3000;
initDb()
  .catch(e => console.error('DB init failed, falling back to memory:', e.message))
  .finally(() => server.listen(PORT, () => console.log('Quick Dial running on ' + PORT)));
