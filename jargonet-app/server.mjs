// Self-hosted entry point for the Jargonet chat app.
//
// Serves the static client from web/ and the JSON API on the same origin, so
// the session cookie is first-party and no CORS is involved. The router,
// password, session, limiter and validation modules are the ones already in
// functions/; only the managed-runtime bindings (database client and request
// context) are replaced here.
//
// Two storage modes:
//
//   local   (default) A SQLite file inside the project, the supported
//           persistence model for a single-port deployment. Set DATA_DIR to
//           move it.
//
//   proxy   When JARGONET_UPSTREAM holds a base URL (or proxy-upstream.txt
//           holds one), API calls are forwarded to that backend instead. This
//           exists so the page can be served from another domain while the
//           accounts and messages that already live in an existing deployment
//           stay exactly where they are, instead of starting from an empty
//           database. Static files always come from this repository.
//
// The session cookie is `__Host-app_auth.session`, which by definition carries
// no Domain attribute and therefore binds to whichever host sets it. A
// forwarded Set-Cookie is stored for this domain, so proxying keeps people
// logged in without rewriting anything.

import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createSqliteClient } from './db-sqlite.mjs';
import { createApplication } from './functions/router.mjs';

const projectDir = dirname(fileURLToPath(import.meta.url));
const webDir = join(projectDir, 'web');
const dataDir = process.env.DATA_DIR || join(projectDir, 'data');
const port = Number(process.env.PORT) || 3000;

const UPSTREAM_FILE = join(projectDir, 'proxy-upstream.txt');
const upstream = (
  process.env.JARGONET_UPSTREAM
  || (existsSync(UPSTREAM_FILE) ? readFileSync(UPSTREAM_FILE, 'utf8') : '')
).trim().replace(/\/+$/, '');

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

// `origin` is deliberately omitted: the router then falls back to comparing the
// browser Origin against this request's own Host header, which is what makes
// the app deployable on any domain without a rebuild.
let handle = null;

if (!upstream) {
  mkdirSync(dataDir, { recursive: true });
  const db = createSqliteClient(join(dataDir, 'jargonet.db'));
  db.exec(readFileSync(join(projectDir, 'schema.sqlite.sql'), 'utf8'));

  // One-shot wipe, for clearing throwaway accounts out of a deployed database.
  // The flag holds a token; the marker in the data directory records the token
  // already applied. A wipe runs only when the two differ, so re-uploading the
  // project cannot empty a live database again, and a new token can be used
  // deliberately when another clear-out is wanted.
  const resetFlag = join(projectDir, 'reset-db.flag');
  const resetMarker = join(dataDir, '.reset-done');
  if (existsSync(resetFlag)) {
    const token = readFileSync(resetFlag, 'utf8').trim() || 'reset';
    const applied = existsSync(resetMarker) ? readFileSync(resetMarker, 'utf8').trim() : '';
    if (token !== applied) {
      for (const table of [
        'relay_packets', 'room_members', 'messages', 'rooms',
        'friendships', 'friend_requests', 'auth_limiter', 'sessions', 'users',
      ]) {
        db.exec(`DELETE FROM ${table}`);
      }
      writeFileSync(resetMarker, token);
      console.log('database reset: application rows cleared');
    }
  }

  handle = createApplication({ db, origin: () => undefined });
}

function isApiPath(pathname) {
  return pathname === '/api' || pathname.startsWith('/api/') || pathname.startsWith('/functions/v1/app');
}

function normaliseApiPath(pathname) {
  if (pathname.startsWith('/api')) return `/functions/v1/app${pathname}`;
  return pathname;
}

async function serveStatic(res, pathname) {
  const relative = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1));
  const target = normalize(join(webDir, relative));

  // Reject anything that escapes web/.
  if (!target.startsWith(webDir + sep) && target !== webDir) {
    res.writeHead(403).end('forbidden');
    return;
  }

  try {
    const body = await readFile(target);
    const extension = target.slice(target.lastIndexOf('.'));
    // Code and markup are revalidated on every load. A cached app.js next to a
    // fresh index.html renders a blank page, and the previous five-minute
    // max-age did exactly that right after a deploy.
    const isCode = extension === '.html' || extension === '.js' || extension === '.css';
    res.writeHead(200, {
      'content-type': CONTENT_TYPES[extension] || 'application/octet-stream',
      'cache-control': isCode ? 'no-cache' : 'public, max-age=300',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('not found');
  }
}

// Forwards one API call to the existing backend. The request is rebuilt rather
// than piped so the Origin header can be set to the upstream host: that backend
// rejects cross-origin writes, and from its point of view this server is the
// browser.
async function proxyApi(req, res, url) {
  const target = new URL(upstream);
  const outgoing = new URL(url.pathname + url.search, target.origin);

  const headers = new Headers();
  const contentType = req.headers['content-type'];
  if (contentType) headers.set('content-type', contentType);
  if (req.headers.cookie) headers.set('cookie', req.headers.cookie);
  headers.set('origin', target.origin);
  headers.set('accept', 'application/json');

  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 65536) {
        res.writeHead(413, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'payload_too_large' }));
        return;
      }
      chunks.push(chunk);
    }
    body = Buffer.concat(chunks);
  }

  const upstreamResponse = await fetch(outgoing, {
    method: req.method,
    headers,
    body,
    redirect: 'manual',
  });

  const outHeaders = {};
  for (const [key, value] of upstreamResponse.headers) {
    if (key === 'set-cookie' || key === 'transfer-encoding' || key === 'connection') continue;
    outHeaders[key] = value;
  }

  const cookies = typeof upstreamResponse.headers.getSetCookie === 'function'
    ? upstreamResponse.headers.getSetCookie()
    : [];
  if (cookies.length > 0) outHeaders['set-cookie'] = cookies;

  res.writeHead(upstreamResponse.status, outHeaders);
  res.end(Buffer.from(await upstreamResponse.arrayBuffer()));
}

function toRequest(req, url) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(key, Array.isArray(value) ? value.join(', ') : value);
  }

  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = req;
    init.duplex = 'half';
  }
  return new Request(url, init);
}

async function writeResponse(res, response) {
  const headers = {};
  for (const [key, value] of response.headers) headers[key] = value;
  res.writeHead(response.status, headers);
  if (!response.body) {
    res.end();
    return;
  }
  res.end(Buffer.from(await response.arrayBuffer()));
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (!isApiPath(url.pathname)) {
      await serveStatic(res, url.pathname);
      return;
    }

    url.pathname = normaliseApiPath(url.pathname);

    if (upstream) {
      await proxyApi(req, res, url);
      return;
    }

    const response = await handle({ request: toRequest(req, url) });
    await writeResponse(res, response);
  } catch {
    if (!res.headersSent) {
      res.writeHead(503, { 'content-type': 'application/json; charset=utf-8' });
    }
    res.end(JSON.stringify({ error: 'service_unavailable' }));
  }
});

server.listen(port, '0.0.0.0', () => {
  console.log(`jargonet-chat listening on 0.0.0.0:${port}${upstream ? ` (api -> ${upstream})` : ' (api -> local sqlite)'}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
