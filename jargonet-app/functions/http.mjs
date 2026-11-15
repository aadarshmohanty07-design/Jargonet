// Fixed-origin HTTP helpers. Application identity comes only from this app's
// own session cookie; platform identity is never used as a fallback.

export const PUBLIC_ORIGIN = 'https://jargonet-chat-o3h47ihndgx.qoder.website';
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

// Same-origin check for state-changing requests. When `origin` is supplied the
// browser Origin must match that exact host. When it is omitted the request's
// own Host header is the reference, which keeps the check correct behind a
// TLS-terminating proxy where the internal scheme is http but the browser
// Origin is https. Only the host is compared, because scheme and port are
// rewritten by the proxy in front of the app.
export function requireTrustedOrigin(request, origin) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return;

  const supplied = request.headers.get('origin');
  if (!supplied) throw new AppError('origin_forbidden', 403);

  let suppliedHost;
  try { suppliedHost = new URL(supplied).host; } catch { throw new AppError('origin_forbidden', 403); }

  let expectedHost;
  if (origin) {
    try { expectedHost = new URL(origin).host; } catch { throw new AppError('application_auth_not_configured', 503); }
  } else {
    expectedHost = request.headers.get('host') || new URL(request.url).host;
  }
  if (!expectedHost || suppliedHost !== expectedHost) throw new AppError('origin_forbidden', 403);
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
