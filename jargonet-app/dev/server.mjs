import { createServer } from 'node:https';
import { readFile, realpath, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, extname, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

export async function startLocal({ root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), port = 8443, cert, key } = {}) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid_local_configuration');
  const origin = `https://localhost:${port}`;
  const { createFakeDb } = await import(pathToFileURL(resolve(root, 'dev/fake-db.mjs')));
  const { createApplication } = await import(pathToFileURL(resolve(root, 'functions/router.mjs')));
  const db = createFakeDb();
  const handle = createApplication({ db, origin });
  const web = await realpath(resolve(root, 'web'));

  const server = createServer({ cert: await readFile(cert), key: await readFile(key) }, async (req, res) => {
    try {
      const url = new URL(req.url, origin);
      if (url.origin !== origin) throw new Error('invalid_origin');
      if (url.pathname === '/__local_health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ localOnly: true }));
        return;
      }
      if (url.pathname.startsWith('/functions/v1/app/')) {
        const chunks = [];
        let size = 0;
        for await (const chunk of req) {
          size += chunk.length;
          if (size > 16384) { res.writeHead(413); res.end(); return; }
          chunks.push(chunk);
        }
        const request = new Request(url, {
          method: req.method,
          headers: req.headers,
          ...(req.method === 'GET' || req.method === 'HEAD' ? {} : { body: Buffer.concat(chunks) }),
        });
        const response = await handle({ request, requestId: crypto.randomUUID() });
        const headers = Object.fromEntries(response.headers);
        delete headers['set-cookie'];
        res.writeHead(response.status, { ...headers, 'set-cookie': response.headers.getSetCookie() });
        res.end(Buffer.from(await response.arrayBuffer()));
        return;
      }
      if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405); res.end(); return; }
      const file = await realpath(resolve(web, '.' + decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname)));
      if (!file.startsWith(web + sep) || !(await stat(file)).isFile()) throw new Error('not_found');
      const types = {
        '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
        '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
      };
      if (!types[extname(file)]) throw new Error('not_found');
      res.writeHead(200, { 'content-type': types[extname(file)], 'cache-control': 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : await readFile(file));
    } catch {
      if (!res.headersSent) res.writeHead(404);
      res.end();
    }
  });

  await new Promise((done, fail) => { server.once('error', fail); server.listen(port, '127.0.0.1', done); });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: {
    port: { type: 'string', default: '8443' },
    cert: { type: 'string' },
    key: { type: 'string' },
  } });
  startLocal({ port: Number(values.port), cert: values.cert, key: values.key })
    .then(() => console.log(`Jargonet local: https://localhost:${values.port} (in-memory database)`))
    .catch(() => { console.error('Local startup failed: check certificate/key paths and port availability.'); process.exitCode = 1; });
}
