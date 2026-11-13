// Pure input validation. No database access.

import { AppError } from './http.mjs';

export const USERNAME_MIN_CHARS = 3;
export const USERNAME_MAX_CHARS = 32;
export const PASSWORD_MIN_CHARS = 8;
export const PASSWORD_MAX_BYTES = 256;
export const MESSAGE_MAX_CHARS = 4000;
export const MESSAGE_MAX_BYTES = 16000;
export const KEY_MAX_CHARS = 1024;
export const KEY_ALGORITHMS = new Set(['X25519', 'Ed25519', 'ECDH', 'AES-GCM', 'P-256']);

export function canonicalUsername(raw) {
  if (typeof raw !== 'string') throw new AppError('invalid_username', 400);
  const canonical = raw.trim().toLowerCase();
  if (canonical.length < USERNAME_MIN_CHARS || canonical.length > USERNAME_MAX_CHARS) {
    throw new AppError('invalid_username', 400);
  }
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(canonical)) throw new AppError('invalid_username', 400);
  return canonical;
}

export function validatePassword(raw) {
  if (typeof raw !== 'string') throw new AppError('invalid_password', 400);
  if ([...raw].length < PASSWORD_MIN_CHARS) throw new AppError('invalid_password', 400);
  if (new TextEncoder().encode(raw).length > PASSWORD_MAX_BYTES) throw new AppError('invalid_password', 400);
  return raw;
}

function base64ish(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= KEY_MAX_CHARS
    && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value);
}

export function validateKeyMaterial(body) {
  const publicKey = body?.publicKey;
  const privateKey = body?.privateKey;
  const algorithm = body?.keyAlgorithm;
  if (!base64ish(publicKey) || !base64ish(privateKey)) throw new AppError('invalid_keys', 400);
  if (publicKey === privateKey) throw new AppError('invalid_keys', 400);
  if (!KEY_ALGORITHMS.has(algorithm)) throw new AppError('invalid_keys', 400);
  return { publicKey, privateKey, algorithm };
}

export function validateMessage(raw) {
  if (typeof raw !== 'string') throw new AppError('invalid_message', 400);
  const text = raw.trim();
  if (!text) throw new AppError('invalid_message', 400);
  if ([...text].length > MESSAGE_MAX_CHARS) throw new AppError('invalid_message', 400);
  if (new TextEncoder().encode(text).length > MESSAGE_MAX_BYTES) throw new AppError('invalid_message', 400);
  return text;
}

export function isUuid(value) {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
}
