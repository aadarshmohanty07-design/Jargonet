// Self-hosted entry point for the Jargonet chat app.
//
// Serves the static client from web/ and the JSON API on the same origin, so
// the session cookie is first-party and no CORS is involved. The router,
// password, session, limiter and validation modules are the ones already in
// functions/; only the managed-runtime bindings (database client and request
// context) are replaced here.
//
// Storage is a SQLite file inside the project, which is the supported
// persistence model for a single-port deployment. Set DATA_DIR to move it.

import { createServer } from 'node:http';
import { mkdirSync, readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createSqliteClient } from './db-sqlite.mjs';
import { createApplication } from './functions/router.mjs';

const projectDir = dirname(fileURLToPath(import.meta.url));
const webDir = join(projectDir, 'web');
const dataDir = process.env.DATA_DIR || join(projectDir, 'data');
const port = Number(process.env.PORT) || 3000;

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

mkdirSync(dataDir, { recursive: true });

const db = createSqliteClient(join(dataDir, 'jargonet.db'));
db.exec(readFileSync(join(projectDir, 'schema.sqlite.sql'), 'utf8'));

// `origin` is deliberately omitted: the router then falls back to comparing the
// browser Origin against this request's own Host header, which is what makes
// the app deployable on any domain without a rebuild.
const handle = createApplication({ db, origin: () => undefined });

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
    res.writeHead(200, {
      'content-type': CONTENT_TYPES[extension] || 'application/octet-stream',
      'cache-control': extension === '.html' ? 'no-cache' : 'public, max-age=300',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('not found');
  }
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
  console.log(`jargonet-chat listening on 0.0.0.0:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
