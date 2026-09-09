# Quick Dial (web)

One keypad, two kinds of call:

- **Phone codes** open your dialer with the number filled in. Needs a SIM.
- **App codes** call another Quick Dial user by ID over the internet. No SIM needed,
  works on tablets and laptops, audio goes peer-to-peer.

## Run it

    npm install
    npm start

Open http://localhost:3000

## Deploy free on Render

1. Push this folder to a GitHub repo.
2. render.com -> New -> Web Service -> pick the repo.
3. Build command `npm install`, start command `npm start`. Free instance type.
4. Open the URL it gives you and add it to your home screen.

Render's free tier sleeps after inactivity, so the first call after a quiet
period takes a few seconds to wake the server.

## How app calls work

`server.js` only relays connection setup between two users. The voice itself
is a direct peer-to-peer WebRTC stream and never passes through the server.

Both people need the page open — a browser cannot ring an app that is closed.
If ringing while closed matters, that needs a native app with push notifications.

Some restrictive networks (corporate Wi-Fi, some mobile carrier NAT) block
peer-to-peer. Adding a TURN relay server fixes that, but TURN carries the audio
and so costs money to run.
