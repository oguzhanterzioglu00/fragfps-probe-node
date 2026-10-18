import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import { GameDig } from 'gamedig';

const port = Number(process.env.PORT || 10000);
const secret = String(process.env.PROBE_SHARED_SECRET || '');
const region = String(process.env.PROBE_REGION || 'global').slice(0, 16);
const maxConcurrent = Math.max(1, Math.min(20, Number(process.env.PROBE_MAX_CONCURRENT || 8)));
let activeQueries = 0;
let minuteWindow = Math.floor(Date.now() / 60000);
let minuteQueries = 0;

function reply(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store, max-age=0',
    'x-content-type-options': 'nosniff'
  });
  response.end(body);
}

function publicIpv4(value) {
  if (net.isIP(value) !== 4) return false;
  const [a, b, c] = value.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function authorized(request, body) {
  if (secret.length < 32) return false;
  const timestamp = String(request.headers['x-fragfps-timestamp'] || '');
  const signature = String(request.headers['x-fragfps-signature'] || '');
  if (!/^\d{10}$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 60) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}\n${body}`).digest('hex');
  if (!/^[a-f0-9]{64}$/.test(signature)) return false;
  return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
}

function playerRow(player) {
  const raw = player?.raw || {};
  const seconds = Math.max(0, Math.floor(Number(raw.time ?? player?.time ?? 0)));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  return [
    String(player?.name || '').slice(0, 48),
    Number(raw.score ?? player?.score ?? 0) || 0,
    `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`
  ];
}

function normalize(state) {
  const raw = state.raw || {};
  const players = Array.isArray(state.players) ? state.players : [];
  const bots = Array.isArray(state.bots) ? state.bots : [];
  const rules = raw.rules && typeof raw.rules === 'object' && !Array.isArray(raw.rules) ? raw.rules : undefined;
  const scan = {
    name: String(state.name || '').slice(0, 100),
    map: String(state.map || 'unknown').slice(0, 64),
    players: Number(raw.numplayers ?? players.length + bots.length) || 0,
    bots: Number(raw.numbots ?? bots.length) || 0,
    max: Number(state.maxplayers || raw.maxplayers || 1) || 1,
    latency: Number(state.ping || 0) || 0,
    playerList: [...players, ...bots].slice(0, 128).map(playerRow),
    protocol: String(raw.protocol ?? '48'),
    engine: 'GoldSrc/Steam',
    folder: String(raw.folder || 'cstrike').toLowerCase(),
    game: String(raw.game || 'Counter-Strike 1.6').slice(0, 120),
    appId: Number(raw.appId ?? 10),
    version: String(state.version || raw.version || '').slice(0, 80),
    serverType: String(raw.listentype || raw.serverType || '').slice(0, 1),
    environment: String(raw.environment || '').slice(0, 1),
    passworded: Boolean(state.password),
    vac: Boolean(raw.secure),
    queryPort: Number(state.queryPort || 0) || undefined
  };
  if (rules) scan.rules = rules;
  return scan;
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16384) throw new Error('request_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

const server = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url === '/health') {
    reply(response, secret.length >= 32 ? 200 : 503, {
      ok: secret.length >= 32,
      service: 'fragfps-probe-node',
      region,
      activeQueries,
      uptime: Math.floor(process.uptime())
    });
    return;
  }
  if (request.method !== 'POST' || request.url !== '/query') {
    reply(response, 404, { ok: false, error: 'not_found' });
    return;
  }
  try {
    const body = await readBody(request);
    if (!authorized(request, body)) {
      reply(response, 401, { ok: false, error: 'unauthorized' });
      return;
    }
    const currentWindow = Math.floor(Date.now() / 60000);
    if (currentWindow !== minuteWindow) {
      minuteWindow = currentWindow;
      minuteQueries = 0;
    }
    minuteQueries += 1;
    if (minuteQueries > 180 || activeQueries >= maxConcurrent) {
      reply(response, 429, { ok: false, error: 'busy' });
      return;
    }
    const input = JSON.parse(body);
    const host = String(input.host || '');
    const gamePort = Number(input.port || 27015);
    if (!publicIpv4(host) || !Number.isInteger(gamePort) || gamePort < 1 || gamePort > 65535) {
      reply(response, 422, { ok: false, error: 'invalid_target' });
      return;
    }
    activeQueries += 1;
    try {
      const state = await GameDig.query({
        type: 'counterstrike16',
        host,
        port: gamePort,
        givenPortOnly: true,
        requestRules: Boolean(input.includeRules),
        socketTimeout: 2500,
        attemptTimeout: 7000,
        maxRetries: 1
      });
      const scan = normalize(state);
      if (scan.folder !== 'cstrike' || scan.appId !== 10) {
        reply(response, 422, { ok: false, error: 'not_cs16' });
        return;
      }
      reply(response, 200, { ok: true, scan });
    } finally {
      activeQueries -= 1;
    }
  } catch (error) {
    reply(response, 422, { ok: false, error: error?.message === 'request_too_large' ? 'request_too_large' : 'server_unreachable' });
  }
});

server.headersTimeout = 10000;
server.requestTimeout = 12000;
server.listen(port, '0.0.0.0', () => {
  console.log(`FragFPS probe node listening on ${port} (${region})`);
});
