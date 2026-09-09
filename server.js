// Signalling server for Quick Dial.
// It only passes connection setup messages between two users.
// The audio itself flows peer-to-peer and never touches this server.

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
app.use(express.static('public'));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const online = new Map();   // userId -> socket

function send(socket, payload) {
  if (socket && socket.readyState === 1) socket.send(JSON.stringify(payload));
}

wss.on('connection', (socket) => {
  socket.userId = null;

  socket.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    if (msg.type === 'register') {
      const id = String(msg.id || '').trim().toLowerCase();
      if (!id) return;

      // Bump any previous session using this id.
      const existing = online.get(id);
      if (existing && existing !== socket) {
        send(existing, { type: 'replaced' });
        existing.close();
      }
      socket.userId = id;
      online.set(id, socket);
      send(socket, { type: 'registered', id });
      return;
    }

    // Everything else is relayed to msg.to
    const to = String(msg.to || '').trim().toLowerCase();
    const target = online.get(to);

    if (!target) {
      send(socket, { type: 'unreachable', to });
      return;
    }
    send(target, { ...msg, from: socket.userId });
  });

  socket.on('close', () => {
    if (socket.userId && online.get(socket.userId) === socket) {
      online.delete(socket.userId);
    }
  });
});

// Drop dead connections so ids don't stay stuck online.
setInterval(() => {
  wss.clients.forEach((s) => {
    if (s.isAlive === false) return s.terminate();
    s.isAlive = false;
    s.ping();
  });
}, 30000);
wss.on('connection', (s) => {
  s.isAlive = true;
  s.on('pong', () => { s.isAlive = true; });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Quick Dial running on ' + PORT));
