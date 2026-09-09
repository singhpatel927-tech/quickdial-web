const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
app.use(express.static('public'));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const memory = new Map();          // id -> { salt, hash }
let pool = null;

async function initDb() {
  if (!process.env.DATABASE_URL) {
    console.log('No DATABASE_URL set - accounts are in memory only.');
    return;
  }
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id   TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('Accounts stored in Postgres.');
}

async function getUser(id) {
  if (!pool) return memory.get(id) || null;
  const r = await pool.query('SELECT salt, hash FROM users WHERE id = $1', [id]);
  return r.rows[0] || null;
}

async function putUser(id, salt, hash) {
  if (!pool) { memory.set(id, { salt, hash }); return; }
  await pool.query('INSERT INTO users (id, salt, hash) VALUES ($1, $2, $3)', [id, salt, hash]);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verify(password, user) {
  const attempt = hashPassword(password, user.salt);
  const a = Buffer.from(attempt, 'hex');
  const b = Buffer.from(user.hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

const attempts = new Map();

function tooManyAttempts(ip) {
  const rec = attempts.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.until) { attempts.delete(ip); return false; }
  return rec.count >= 8;
}

function noteFailure(ip) {
  const rec = attempts.get(ip) || { count: 0, until: Date.now() + 15 * 60 * 1000 };
  rec.count += 1;
  attempts.set(ip, rec);
}

const online = new Map();

function send(socket, payload) {
  if (socket && socket.readyState === 1) socket.send(JSON.stringify(payload));
}

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

      if (!/^[a-z0-9_.-]{2,20}$/.test(id)) {
        return send(socket, { type: 'authfail', reason: 'That ID format is not allowed' });
      }
      if (password.length < 6) {
        return send(socket, { type: 'authfail', reason: 'Password must be at least 6 characters' });
      }
      if (tooManyAttempts(socket.ip)) {
        return send(socket, { type: 'authfail', reason: 'Too many attempts. Try again in 15 minutes' });
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
        const hash = hashPassword(password, salt);
        try { await putUser(id, salt, hash); }
        catch (e) { return send(socket, { type: 'authfail', reason: 'That ID was just taken' }); }
        user = { salt, hash };
      } else {
        if (msg.mode === 'signup') {
          return send(socket, { type: 'authfail', reason: 'That ID is already taken' });
        }
        if (!verify(password, user)) {
          noteFailure(socket.ip);
          return send(socket, { type: 'authfail', reason: 'Wrong password' });
        }
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
