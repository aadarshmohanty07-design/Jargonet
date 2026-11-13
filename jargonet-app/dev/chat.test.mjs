import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '../functions/router.mjs';
import { SESSION_COOKIE } from '../functions/sessions.mjs';
import { createFakeDb } from './fake-db.mjs';

const ORIGIN = 'https://chat.test';
const PASSWORD = `pw-${crypto.randomUUID()}-${crypto.randomUUID()}`;

function keys() {
  return {
    publicKey: Buffer.from(`public-${crypto.randomUUID()}`).toString('base64'),
    privateKey: Buffer.from(`private-${crypto.randomUUID()}`).toString('base64'),
    keyAlgorithm: 'X25519',
  };
}

function fixture() {
  const db = createFakeDb();
  const handle = createApplication({ db, origin: ORIGIN });
  return { db, handle };
}

function ctx(path, { method = 'GET', body, cookie, origin = ORIGIN } = {}) {
  const headers = { origin };
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  return {
    request: new Request(`${ORIGIN}/functions/v1/app${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
    requestId: 'local-test',
  };
}

async function call(handle, context) {
  const response = await handle(context);
  let body = null;
  try { body = await response.clone().json(); } catch { body = null; }
  return { status: response.status, body, setCookie: response.headers.get('set-cookie'), headers: response.headers };
}

const cookiePair = (result) => result.setCookie?.split(';')[0] ?? null;
const unique = (prefix) => `${prefix}${crypto.randomUUID().replace(/-/g, '').slice(0, 8)}`;
const register = (handle, username, extra = {}) => call(handle, ctx('/api/register', {
  method: 'POST', body: { username, password: PASSWORD, ...keys(), ...extra },
}));
const login = (handle, username, password = PASSWORD) => call(handle, ctx('/api/login', {
  method: 'POST', body: { username, password },
}));
const me = (handle, cookie) => call(handle, ctx('/api/me', { cookie }));
const state = (handle, cookie) => call(handle, ctx('/api/state', { cookie }));
const presence = (handle, cookie) => call(handle, ctx('/api/presence', { method: 'POST', cookie }));
const messages = (handle, cookie, friendId) => call(handle, ctx(`/api/messages?friendId=${friendId}`, { cookie }));

test('register: canonical username, cookie flags, key material in own profile only', async () => {
  const { db, handle } = fixture();
  const created = await register(handle, '  Alice_01  ');
  assert.equal(created.status, 201);
  assert.equal(created.body.user.username, 'alice_01');
  assert.deepEqual(Object.keys(created.body.user).sort(), ['id', 'username']);

  const cookie = cookiePair(created);
  assert.ok(cookie?.startsWith(`${SESSION_COOKIE}=`));
  assert.match(created.setCookie, /HttpOnly/);
  assert.match(created.setCookie, /Secure/);
  assert.match(created.setCookie, /SameSite=Lax/);
  assert.match(created.setCookie, /Path=\//);
  assert.ok(!/Domain=/i.test(created.setCookie));

  const profile = await me(handle, cookie);
  assert.equal(profile.status, 200);
  assert.equal(Buffer.from(profile.body.user.publicKey, 'base64').toString().startsWith('public-'), true);
  assert.equal(Buffer.from(profile.body.user.privateKey, 'base64').toString().startsWith('private-'), true);
  assert.equal(profile.body.user.keyAlgorithm, 'X25519');

  const stored = JSON.stringify([...db.dump('users'), ...db.dump('sessions')]);
  assert.ok(!stored.includes(PASSWORD), 'plaintext password must not be stored');
});

test('presence: online directory updates from a heartbeat and expires', async () => {
  const { db, handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const bob = await register(handle, unique('bob'));
  const aliceCookie = cookiePair(alice);
  const bobCookie = cookiePair(bob);

  let view = await state(handle, aliceCookie);
  assert.equal(view.status, 200);
  assert.equal(view.body.online.length, 1);
  assert.equal(view.body.online[0].id, bob.body.user.id);

  const old = new Date(Date.now() - 60_000).toISOString();
  await db.from('users').update({ last_seen_at: old }).eq('id', bob.body.user.id);
  view = await state(handle, aliceCookie);
  assert.equal(view.body.online.length, 0, 'stale presence is hidden');

  assert.equal((await presence(handle, bobCookie)).status, 200);
  view = await state(handle, aliceCookie);
  assert.equal(view.body.online.length, 1, 'heartbeat restores presence');
});

test('friend request and accept creates a two-way friendship', async () => {
  const { handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const bob = await register(handle, unique('bob'));
  const aliceCookie = cookiePair(alice);
  const bobCookie = cookiePair(bob);

  const sent = await call(handle, ctx('/api/friends/request', {
    method: 'POST', cookie: aliceCookie, body: { userId: bob.body.user.id },
  }));
  assert.equal(sent.status, 201);

  const outgoing = await state(handle, aliceCookie);
  assert.equal(outgoing.body.online.find((person) => person.id === bob.body.user.id)?.request, 'outgoing');

  const incoming = await state(handle, bobCookie);
  assert.equal(incoming.body.incoming.length, 1);
  assert.equal(incoming.body.incoming[0].from.id, alice.body.user.id);
  const requestId = incoming.body.incoming[0].id;

  const accepted = await call(handle, ctx('/api/friends/accept', {
    method: 'POST', cookie: bobCookie, body: { requestId },
  }));
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.friend.id, alice.body.user.id);

  const aliceState = await state(handle, aliceCookie);
  const bobState = await state(handle, bobCookie);
  assert.ok(aliceState.body.friends.some((friend) => friend.id === bob.body.user.id));
  assert.ok(bobState.body.friends.some((friend) => friend.id === alice.body.user.id));

  const duplicate = await call(handle, ctx('/api/friends/request', {
    method: 'POST', cookie: aliceCookie, body: { userId: bob.body.user.id },
  }));
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.error, 'already_friends');
});

test('messages: friends exchange text, non-friends cannot read or write', async () => {
  const { handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const bob = await register(handle, unique('bob'));
  const carol = await register(handle, unique('carol'));
  const aliceCookie = cookiePair(alice);
  const bobCookie = cookiePair(bob);
  const carolCookie = cookiePair(carol);

  const sent = await call(handle, ctx('/api/friends/request', {
    method: 'POST', cookie: aliceCookie, body: { userId: bob.body.user.id },
  }));
  assert.equal(sent.status, 201);
  const bobState = await state(handle, bobCookie);
  const accepted = await call(handle, ctx('/api/friends/accept', {
    method: 'POST', cookie: bobCookie, body: { requestId: bobState.body.incoming[0].id },
  }));
  assert.equal(accepted.status, 200);

  const first = await call(handle, ctx('/api/messages', {
    method: 'POST', cookie: aliceCookie, body: { friendId: bob.body.user.id, text: 'hello bob' },
  }));
  assert.equal(first.status, 201);
  await new Promise((resolve) => setTimeout(resolve, 4));
  const second = await call(handle, ctx('/api/messages', {
    method: 'POST', cookie: bobCookie, body: { friendId: alice.body.user.id, text: 'hello alice' },
  }));
  assert.equal(second.status, 201);

  const thread = await messages(handle, bobCookie, alice.body.user.id);
  assert.equal(thread.status, 200);
  assert.deepEqual(thread.body.messages.map((message) => message.text), ['hello bob', 'hello alice']);
  assert.equal(Buffer.from(thread.body.friend.publicKey, 'base64').toString().startsWith('public-'), true);
  assert.equal('privateKey' in thread.body.friend, false);

  const deniedRead = await messages(handle, carolCookie, alice.body.user.id);
  assert.equal(deniedRead.status, 403);
  assert.equal(deniedRead.body.error, 'not_friends');
  const deniedWrite = await call(handle, ctx('/api/messages', {
    method: 'POST', cookie: carolCookie, body: { friendId: alice.body.user.id, text: 'nope' },
  }));
  assert.equal(deniedWrite.status, 403);

  const ownState = await state(handle, aliceCookie);
  assert.ok(!JSON.stringify(ownState.body).includes('privateKey'), 'state must not leak private keys');
});

test('decline and re-request reuse the same request row', async () => {
  const { db, handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const bob = await register(handle, unique('bob'));
  const aliceCookie = cookiePair(alice);
  const bobCookie = cookiePair(bob);

  await call(handle, ctx('/api/friends/request', {
    method: 'POST', cookie: aliceCookie, body: { userId: bob.body.user.id },
  }));
  let bobState = await state(handle, bobCookie);
  const requestId = bobState.body.incoming[0].id;
  const declined = await call(handle, ctx('/api/friends/decline', {
    method: 'POST', cookie: bobCookie, body: { requestId },
  }));
  assert.equal(declined.status, 200);
  bobState = await state(handle, bobCookie);
  assert.equal(bobState.body.incoming.length, 0);

  const again = await call(handle, ctx('/api/friends/request', {
    method: 'POST', cookie: aliceCookie, body: { userId: bob.body.user.id },
  }));
  assert.equal(again.status, 200);
  assert.equal(again.body.request.id, requestId);
  assert.equal(db.dump('friend_requests').filter((row) => row.from_user_id === alice.body.user.id).length, 1);
});

test('auth and CSRF failures do not expose data', async () => {
  const { handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const cookie = cookiePair(alice);
  assert.equal((await state(handle, null)).status, 401);
  assert.equal((await me(handle, null)).status, 401);

  const foreign = await call(handle, ctx('/api/presence', {
    method: 'POST', cookie, origin: 'https://evil.test',
  }));
  assert.equal(foreign.status, 403);
  assert.equal(foreign.body.error, 'origin_forbidden');

  const missingOrigin = await call(handle, ctx('/api/logout', { method: 'POST', cookie, origin: null }));
  assert.equal(missingOrigin.status, 403);

  const wrong = await login(handle, unique('ghost'), PASSWORD);
  assert.equal(wrong.status, 401);
  assert.deepEqual(wrong.body, { error: 'invalid_credentials' });

  const logout = await call(handle, ctx('/api/logout', { method: 'POST', cookie }));
  assert.equal(logout.status, 200);
  assert.match(logout.setCookie ?? '', /Max-Age=0/);
  assert.equal((await me(handle, cookie)).status, 401);
});

test('routes: health, unknown path and wrong method', async () => {
  const { handle } = fixture();
  assert.equal((await call(handle, ctx('/api/health'))).status, 200);
  assert.equal((await call(handle, ctx('/api/nope'))).status, 401, 'auth is checked before route lookup');
  const alice = await register(handle, unique('alice'));
  assert.equal((await call(handle, ctx('/api/nope', { cookie: cookiePair(alice) }))).status, 404);
  assert.equal((await call(handle, ctx('/api/state', { method: 'POST', cookie: cookiePair(alice), body: {} }))).status, 405);
});

test('chatrooms: distinct private and public keys, join a chat with private key', async () => {
  const { handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const bob = await register(handle, unique('bob'));
  const aliceCookie = cookiePair(alice);
  const bobCookie = cookiePair(bob);

  // 1. Alice creates a chatroom
  const createRes = await call(handle, ctx('/api/rooms/create', {
    method: 'POST', cookie: aliceCookie, body: { name: 'dark-mesh-hq' },
  }));
  assert.equal(createRes.status, 201);
  assert.ok(createRes.body.room.id);
  assert.equal(createRes.body.room.name, 'dark-mesh-hq');
  assert.ok(createRes.body.room.publicKey);
  assert.ok(createRes.body.room.privateKey);
  assert.notEqual(createRes.body.room.publicKey, createRes.body.room.privateKey);

  const roomPrivKey = createRes.body.room.privateKey;
  const roomId = createRes.body.room.id;

  // 2. Bob joins the chatroom using the private key
  const joinRes = await call(handle, ctx('/api/rooms/join', {
    method: 'POST', cookie: bobCookie, body: { privateKey: roomPrivKey },
  }));
  assert.equal(joinRes.status, 200);
  assert.equal(joinRes.body.room.id, roomId);

  // 3. Alice sends encrypted message with hop trail into the room
  const sendRes = await call(handle, ctx('/api/messages', {
    method: 'POST', cookie: aliceCookie,
    body: {
      roomId,
      ciphertext: 'ENCRYPTED_PAYLOAD_TEST_A2B',
      nonce: 'NONCE_123',
      hopCount: 3,
      hopTrail: '@alice → @relay1 → @relay2 → #dark-mesh-hq',
    },
  }));
  assert.equal(sendRes.status, 201);
  assert.equal(sendRes.body.message.ciphertext, 'ENCRYPTED_PAYLOAD_TEST_A2B');
  assert.equal(sendRes.body.message.hopCount, 3);

  // 4. Bob reads messages from the room
  const readRes = await call(handle, ctx(`/api/messages?roomId=${roomId}`, { cookie: bobCookie }));
  assert.equal(readRes.status, 200);
  assert.equal(readRes.body.room.privateKey, roomPrivKey);
  assert.equal(readRes.body.messages.length, 1);
  assert.equal(readRes.body.messages[0].ciphertext, 'ENCRYPTED_PAYLOAD_TEST_A2B');
  assert.equal(readRes.body.messages[0].hopCount, 3);
});

test('peer hopping: relay queues transmit opaque envelopes and flush', async () => {
  const { handle } = fixture();
  const alice = await register(handle, unique('alice'));
  const relayNode = await register(handle, unique('relay'));
  const aliceCookie = cookiePair(alice);
  const relayCookie = cookiePair(relayNode);

  // Send an onion packet to the relay node
  const sendPacket = await call(handle, ctx('/api/relay/send', {
    method: 'POST', cookie: aliceCookie,
    body: {
      recipientId: relayNode.body.user.id,
      payload: JSON.stringify({ nextRecipientId: 'target-peer-id', innerPayload: 'SEALED_ONION_LAYER' }),
      hopCount: 1,
    },
  }));
  assert.equal(sendPacket.status, 200);
  assert.ok(sendPacket.body.packetId);

  // Relay node polls packets
  const polled = await call(handle, ctx('/api/relay/poll', { cookie: relayCookie }));
  assert.equal(polled.status, 200);
  assert.equal(polled.body.packets.length, 1);
  assert.equal(polled.body.packets[0].recipient_id, relayNode.body.user.id);

  // Subsequent poll returns empty because packets flush (ephemeral / zero traces)
  const emptyPoll = await call(handle, ctx('/api/relay/poll', { cookie: relayCookie }));
  assert.equal(emptyPoll.status, 200);
  assert.equal(emptyPoll.body.packets.length, 0);
});
