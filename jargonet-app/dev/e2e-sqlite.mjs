const BASE = 'http://localhost:3210';
const ORIGIN = BASE;

function cookieOf(response) {
  const raw = response.headers.getSetCookie?.() ?? [];
  for (const value of raw) {
    const match = value.match(/__Host-app_auth\.session=([^;]+)/);
    if (match) return match[1];
  }
  return null;
}

async function call(path, { method = 'GET', token, body } = {}) {
  const headers = { origin: ORIGIN };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.cookie = `__Host-app_auth.session=${token}`;
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: response.status, data, token: cookieOf(response) };
}

function check(label, condition, extra = '') {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!condition) process.exitCode = 1;
}

const keys = (n) => ({
  publicKey: Buffer.from(`pub-${n}-` + 'x'.repeat(24)).toString('base64'),
  privateKey: Buffer.from(`prv-${n}-` + 'y'.repeat(24)).toString('base64'),
  keyAlgorithm: 'AES-GCM',
});

const suffix = Date.now().toString(36).slice(-6);
const aliceName = `alice${suffix}`;
const bobName = `bob${suffix}`;

const a = await call('/api/register', { method: 'POST', body: { username: aliceName, password: 'correct horse battery', ...keys('a') } });
check('register alice', a.status === 201 && a.token, `status=${a.status}`);
const aliceId = a.data?.user?.id;

const b = await call('/api/register', { method: 'POST', body: { username: bobName, password: 'correct horse battery', ...keys('b') } });
check('register bob', b.status === 201 && b.token, `status=${b.status}`);
const bobId = b.data?.user?.id;

const dup = await call('/api/register', { method: 'POST', body: { username: aliceName, password: 'correct horse battery', ...keys('c') } });
check('duplicate username rejected', dup.status === 409, `status=${dup.status}`);

const badOrigin = await fetch(`${BASE}/api/register`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
  body: JSON.stringify({ username: 'x' + suffix, password: 'correct horse battery', ...keys('d') }),
});
check('cross-origin write rejected', badOrigin.status === 403, `status=${badOrigin.status}`);

const login = await call('/api/login', { method: 'POST', body: { username: aliceName, password: 'correct horse battery' } });
check('login alice', login.status === 200 && login.token, `status=${login.status}`);
const alice = login.token;

const wrong = await call('/api/login', { method: 'POST', body: { username: aliceName, password: 'wrong password here' } });
check('wrong password rejected', wrong.status === 401, `status=${wrong.status}`);

const me = await call('/api/me', { token: alice });
check('me returns identity', me.status === 200 && me.data?.user?.username === aliceName, `status=${me.status}`);

const anon = await call('/api/me');
check('unauthenticated me rejected', anon.status === 401, `status=${anon.status}`);

const presence = await call('/api/presence', { method: 'POST', token: alice, body: {} });
check('presence accepted', presence.status === 200, `status=${presence.status}`);

const req = await call('/api/friends/request', { method: 'POST', token: alice, body: { userId: bobId } });
check('friend request sent', req.status === 200 || req.status === 201, `status=${req.status}`);

const bobState = await call('/api/state', { token: b.token });
const incoming = bobState.data?.requests ?? bobState.data?.incoming ?? [];
check('bob sees request', Array.isArray(incoming) && incoming.length === 1, `count=${incoming.length}`);

const requestId = incoming[0]?.id ?? incoming[0]?.requestId;
const accept = await call('/api/friends/accept', { method: 'POST', token: b.token, body: { requestId } });
check('friend request accepted', accept.status === 200, `status=${accept.status}`);

const send = await call('/api/messages', {
  method: 'POST',
  token: alice,
  body: { friendId: bobId, ciphertext: 'ciphertext-alice-1', nonce: 'nonce-1', hopCount: 2, hopTrail: 'a>b' },
});
check('alice sends message', send.status === 200 || send.status === 201, `status=${send.status}`);

const read = await call(`/api/messages?friendId=${aliceId}`, { token: b.token });
const messages = read.data?.messages ?? [];
check('bob reads message', messages.length === 1 && messages[0].ciphertext === 'ciphertext-alice-1', `count=${messages.length}`);
check('message nonce preserved', messages[0]?.nonce === 'nonce-1', `nonce=${messages[0]?.nonce}`);
check('message hop count preserved', messages[0]?.hopCount === 2, `hop=${messages[0]?.hopCount}`);

const room = await call('/api/rooms/create', { method: 'POST', token: alice, body: { name: 'ops-room' } });
check('room created', room.status === 200 || room.status === 201, `status=${room.status}`);
const roomKey = room.data?.room?.privateKey;

const join = await call('/api/rooms/join', { method: 'POST', token: b.token, body: { privateKey: roomKey } });
check('bob joins room by key', join.status === 200 && join.data?.room?.id === room.data?.room?.id, `status=${join.status}`);

const roomSend = await call('/api/messages', {
  method: 'POST',
  token: b.token,
  body: { roomId: room.data?.room?.id, ciphertext: 'room-msg-1', nonce: 'n2' },
});
check('room message sent', roomSend.status === 200 || roomSend.status === 201, `status=${roomSend.status}`);

const relaySend = await call('/api/relay/send', { method: 'POST', token: alice, body: { recipientId: bobId, payload: 'opaque-relay-blob', hopCount: 1 } });
check('relay packet queued', relaySend.status === 200 || relaySend.status === 201, `status=${relaySend.status}`);

const relayPoll = await call('/api/relay/poll', { token: b.token });
const packets = relayPoll.data?.packets ?? [];
check('relay packet delivered', packets.length === 1 && packets[0].payload === 'opaque-relay-blob', `count=${packets.length}`);

const relayAgain = await call('/api/relay/poll', { token: b.token });
check('relay packet flushed after read', (relayAgain.data?.packets ?? []).length === 0, `count=${(relayAgain.data?.packets ?? []).length}`);

const logout = await call('/api/logout', { method: 'POST', token: alice, body: {} });
check('logout', logout.status === 200, `status=${logout.status}`);
const afterLogout = await call('/api/me', { token: alice });
check('session revoked after logout', afterLogout.status === 401, `status=${afterLogout.status}`);

console.log(process.exitCode ? 'SOME CHECKS FAILED' : 'ALL CHECKS PASSED');
