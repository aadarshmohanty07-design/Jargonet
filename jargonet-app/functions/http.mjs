// Fixed-origin HTTP helpers. Application identity comes only from this app's
// own session cookie; platform identity is never used as a fallback.

// Empty means "no fixed origin": the check then derives the trusted host from
// the request itself, so the app runs on whatever domain it is deployed to.
// Set APP_ORIGIN (or fill this in) to pin it to one exact origin.
export const PUBLIC_ORIGIN = '';
export const BODY_LIMIT_BYTES = 16384;

export class AppError extends Error {
  constructor(code, status) {
    super(code);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
  }
}

const NO_STORE = { 'cache-control': 'private, no-store', 'referrer-policy': 'no-referrer' };

export function json(value, status = 200, extra = {}) {
  return Response.json(value, { status, headers: { ...NO_STORE, ...extra } });
}

export function errorJson(code, status, extra = {}) {
  return json({ error: code }, status, extra);
}

export function applicationPath(request) {
  const match = new URL(request.url).pathname.match(/^\/(?:functions\/v1\/)?(?:app|app-d[0-9a-f]{32})(\/.*)?$/);
  if (!match) throw new AppError('not_found', 404);
  return match[1] || '/';
}

// Same-origin check for state-changing requests.
//
// The reference host cannot be taken from `Host` alone: a reverse proxy in front
// of the app is free to rewrite it to an internal address, and then every write
// from a real browser is rejected even though it is perfectly same-origin. That
// is what made account creation fail on the published deployment.
//
// So a request is trusted when either signal says same-origin:
//
//   1. `Sec-Fetch-Site` is same-origin or none. The browser sets this header
//      itself and page script cannot forge it, so a cross-site request cannot
//      claim it. This is the signal that survives any proxy.
//   2. The Origin host matches one of the hosts this request could legitimately
//      have arrived on: the configured origin(s), `X-Forwarded-Host`, or `Host`.
//
// Only the host is compared, never the scheme or port, because those are the
// parts a TLS-terminating proxy rewrites.
function trustedHosts(request, origin) {
  const hosts = new Set();
  const add = (value) => {
    for (const part of String(value).split(',')) {
      const candidate = part.trim();
      if (!candidate) continue;
      try { hosts.add(new URL(candidate.includes('://') ? candidate : `http://${candidate}`).host); } catch { /* ignore */ }
    }
  };
  if (origin) add(origin);
  const forwarded = request.headers.get('x-forwarded-host');
  if (forwarded) add(forwarded);
  const host = request.headers.get('host');
  if (host) add(host);
  return hosts;
}

export function requireTrustedOrigin(request, origin) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return;

  const site = request.headers.get('sec-fetch-site');
  if (site === 'same-origin' || site === 'none') return;

  const supplied = request.headers.get('origin');
  if (!supplied) throw new AppError('origin_forbidden', 403);

  let suppliedHost;
  try { suppliedHost = new URL(supplied).host; } catch { throw new AppError('origin_forbidden', 403); }

  const hosts = trustedHosts(request, origin);
  if (hosts.size === 0) throw new AppError('application_auth_not_configured', 503);
  if (!hosts.has(suppliedHost)) throw new AppError('origin_forbidden', 403);
}

export async function readJson(request, maxBytes = BODY_LIMIT_BYTES) {
  if (request.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') {
    throw new AppError('invalid_input', 400);
  }
  const reader = request.body?.getReader();
  if (!reader) throw new AppError('invalid_input', 400);
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) {
        await reader.cancel();
        throw new AppError('payload_too_large', 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new AppError('invalid_input', 400);
  }
}

export function rows(result) {
  if (result?.error || !Array.isArray(result?.data)) throw new AppError('database_unavailable', 503);
  return result.data;
}
