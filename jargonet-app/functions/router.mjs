import { AppError, applicationPath, errorJson, json, readJson, requireTrustedOrigin, rows } from './http.mjs';
import { canonicalUsername, isUuid, validateKeyMaterial, validateMessage, validatePassword } from './validate.mjs';
import { hashPassword, verifyPassword, verifyPasswordAgainstDummy } from './passwords.mjs';
import {
  SESSION_TTL_MS, clearSessionCookie, createSession, revokeSession, sessionCookie, validateSession,
} from './sessions.mjs';
import { consume } from './limiter.mjs';

const SESSION_TTL_SECONDS = Math.floor(SESSION_TTL_MS / 1000);
const PRESENCE_WINDOW_MS = 35 * 1000;
const USER_SCAN_LIMIT = 500;
const FRIEND_SCAN_LIMIT = 500;
const REQUEST_SCAN_LIMIT = 200;
const MESSAGE_PAGE_LIMIT = 200;

class SessionRequired extends Error {
  constructor(state) {
    super('login_required');
    this.state = state;
  }
}

const retryAfter = (result) => ({ 'retry-after': String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))) });

function unauthorized(state) {
  return state === 'invalid'
    ? errorJson('login_required', 401, { 'set-cookie': clearSessionCookie() })
    : errorJson('login_required', 401);
}

async function requireSession(db, request) {
  const result = await validateSession(db, request);
  if (result.state !== 'valid') throw new SessionRequired(result.state);
  return result.session;
}

function publicUser(row) {
  return { id: row.id, username: row.username };
}

function selfView(row) {
  return {
    id: row.id,
    username: row.username,
    publicKey: row.public_key,
    privateKey: row.private_key,
    keyAlgorithm: row.key_algorithm,
    createdAt: row.created_at,
  };
}

function onlineAt(row, now = Date.now()) {
  const lastSeen = Date.parse(row?.last_seen_at);
  return Number.isFinite(lastSeen) && lastSeen >= now - PRESENCE_WINDOW_MS;
}

function conversationKey(left, right) {
  return [left, right].sort().join(':');
}

function messageView(row) {
  return {
    id: row.id,
    senderId: row.sender_id,
    recipientId: row.recipient_id,
    roomId: row.room_id || null,
    ciphertext: row.body,
    text: row.body,
    nonce: row.nonce || '',
    hopCount: row.hop_count || 1,
    hopTrail: row.hop_trail || null,
    createdAt: row.created_at,
  };
}

function formatRoom(row, memberIds = []) {
  return {
    id: row.id,
    name: row.name,
    publicKey: row.public_key,
    privateKey: row.private_key,
    keyAlgorithm: row.key_algorithm,
    createdBy: row.created_by,
    createdAt: row.created_at,
    members: memberIds,
  };
}

async function generateServerRoomKeys() {
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (let i = 0; i < secretBytes.length; i += 1) binary += String.fromCharCode(secretBytes[i]);
  const privateKey = btoa(binary);

  const digestBuffer = await crypto.subtle.digest('SHA-256', secretBytes);
  const digestBytes = new Uint8Array(digestBuffer);
  let digestBinary = '';
  for (let i = 0; i < digestBytes.length; i += 1) digestBinary += String.fromCharCode(digestBytes[i]);
  const publicKey = btoa(digestBinary);

  return {
    publicKey,
    privateKey,
    keyAlgorithm: 'AES-256-GCM',
  };
}

async function ensureConversationRoom(db, userA, userB, optionalKeys = null) {
  const convKey = conversationKey(userA, userB);
  const existingRooms = rows(await db.from('rooms')
    .select('id,name,public_key,private_key,key_algorithm,created_by,created_at')
    .eq('name', `chat:${convKey}`)
    .limit(1));
  let room;
  if (existingRooms.length === 1) {
    room = existingRooms[0];
  } else {
    const roomId = crypto.randomUUID();
    const now = new Date().toISOString();
    let keys = optionalKeys;
    if (!keys || typeof keys.publicKey !== 'string' || typeof keys.privateKey !== 'string') {
      keys = await generateServerRoomKeys();
    }
    const inserted = rows(await db.from('rooms').insertIfAbsent({
      id: roomId,
      name: `chat:${convKey}`,
      public_key: keys.publicKey,
      private_key: keys.privateKey,
      key_algorithm: keys.keyAlgorithm || 'AES-256-GCM',
      created_by: userA,
      created_at: now,
    }, { onConflict: 'id' }).select('id,name,public_key,private_key,key_algorithm,created_by,created_at'));
    room = inserted[0] || (rows(await db.from('rooms').select('*').eq('id', roomId)))[0];
  }
  if (room) {
    const now = new Date().toISOString();
    await db.from('room_members').insertIfAbsent({ room_id: room.id, user_id: userA, joined_at: now }, { onConflict: 'room_id,user_id' });
    await db.from('room_members').insertIfAbsent({ room_id: room.id, user_id: userB, joined_at: now }, { onConflict: 'room_id,user_id' });
  }
  return room;
}

async function loadSelf(db, userId) {
  const found = rows(await db.from('users')
    .select('id,username,public_key,private_key,key_algorithm,created_at')
    .eq('id', userId).limit(1));
  if (found.length !== 1 || typeof found[0]?.username !== 'string') throw new SessionRequired('invalid');
  return found[0];
}

async function loadUser(db, userId) {
  const found = rows(await db.from('users')
    .select('id,username,public_key,key_algorithm,last_seen_at').eq('id', userId).limit(1));
  return found.length === 1 && typeof found[0]?.username === 'string' ? found[0] : null;
}

async function touchPresence(db, userId) {
  const touched = rows(await db.from('users')
    .update({ last_seen_at: new Date().toISOString() })
    .eq('id', userId).select('id'));
  if (touched.length !== 1) throw new SessionRequired('invalid');
}

async function loadDirectory(db) {
  return rows(await db.from('users')
    .select('id,username,last_seen_at')
    .order('username', { ascending: true })
    .limit(USER_SCAN_LIMIT));
}

async function loadFriendIds(db, userId) {
  const list = rows(await db.from('friendships')
    .select('friend_id').eq('user_id', userId).limit(FRIEND_SCAN_LIMIT));
  return new Set(list.map((row) => row.friend_id));
}

async function isFriend(db, userId, friendId) {
  const found = rows(await db.from('friendships')
    .select('friend_id').eq('user_id', userId).eq('friend_id', friendId).limit(1));
  return found.length === 1;
}

async function requestsFor(db, column, userId) {
  const list = rows(await db.from('friend_requests')
    .select('id,from_user_id,to_user_id,status,created_at')
    .eq(column, userId)
    .limit(REQUEST_SCAN_LIMIT));
  return list.filter((row) => row.status === 'pending')
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

async function register(db, request) {
  const body = await readJson(request);
  const username = canonicalUsername(body?.username);
  const password = validatePassword(body?.password);
  const keys = validateKeyMaterial(body);
  const limit = await consume(db, 'register', username);
  if (!limit.allowed) return errorJson('rate_limited', 429, retryAfter(limit));

  const existing = rows(await db.from('users').select('id').eq('username', username).limit(1));
  if (existing.length > 0) return errorJson('username_taken', 409);

  const derived = await hashPassword(password);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const created = rows(await db.from('users').insertIfAbsent({
    id,
    username,
    password_salt: derived.salt,
    password_hash: derived.hash,
    password_iterations: derived.iterations,
    public_key: keys.publicKey,
    private_key: keys.privateKey,
    key_algorithm: keys.algorithm,
    created_at: now,
    last_seen_at: now,
  }, { onConflict: 'username' }).select('id,username'));

  if (created.length !== 1) {
    const winner = rows(await db.from('users').select('id').eq('username', username).limit(1));
    if (winner.length === 1) return errorJson('username_taken', 409);
    return errorJson('registration_unconfirmed', 503);
  }

  const { token } = await createSession(db, id);
  return json({ user: { id, username } }, 201, { 'set-cookie': sessionCookie(token, SESSION_TTL_SECONDS) });
}

async function login(db, request) {
  const body = await readJson(request);
  const username = canonicalUsername(body?.username);
  const limit = await consume(db, 'login', username);
  if (!limit.allowed) return errorJson('rate_limited', 429, retryAfter(limit));

  const password = body?.password;
  if (typeof password !== 'string' || password.length === 0 || new TextEncoder().encode(password).length > 256) {
    throw new AppError('invalid_input', 400);
  }

  const found = rows(await db.from('users')
    .select('id,username,password_salt,password_hash,password_iterations')
    .eq('username', username).limit(1));

  if (found.length !== 1) {
    await verifyPasswordAgainstDummy(password);
    return errorJson('invalid_credentials', 401);
  }

  const user = found[0];
  const ok = await verifyPassword(password, {
    salt: user.password_salt, hash: user.password_hash, iterations: user.password_iterations,
  });
  if (!ok) return errorJson('invalid_credentials', 401);

  await touchPresence(db, user.id);
  const { token } = await createSession(db, user.id);
  return json({ user: { id: user.id, username: user.username } }, 200, {
    'set-cookie': sessionCookie(token, SESSION_TTL_SECONDS),
  });
}

async function logout(db, request) {
  const result = await validateSession(db, request);
  if (result.state === 'valid' && result.session) {
    try {
      await revokeSession(db, result.session.digest);
    } catch {
      return errorJson('logout_unconfirmed', 503);
    }
  }
  return json({ ok: true }, 200, { 'set-cookie': clearSessionCookie() });
}

async function state(db, request) {
  const session = await requireSession(db, request);
  const me = session.userId;
  const now = Date.now();
  const directory = await loadDirectory(db);
  const byId = new Map(directory.map((row) => [row.id, row]));
  const friendIds = await loadFriendIds(db, me);
  const incomingRaw = await requestsFor(db, 'to_user_id', me);
  const outgoingRaw = await requestsFor(db, 'from_user_id', me);
  const incomingFrom = new Set(incomingRaw.map((row) => row.from_user_id));
  const outgoingTo = new Map(outgoingRaw.map((row) => [row.to_user_id, row]));

  const friends = [];
  for (const friendId of friendIds) {
    const row = byId.get(friendId);
    if (!row) continue;
    friends.push({ ...publicUser(row), online: onlineAt(row, now) });
  }
  friends.sort((a, b) => Number(b.online) - Number(a.online) || a.username.localeCompare(b.username));

  const incoming = [];
  for (const row of incomingRaw) {
    const from = byId.get(row.from_user_id);
    if (!from) continue;
    incoming.push({
      id: row.id,
      from: publicUser(from),
      online: onlineAt(from, now),
      createdAt: row.created_at,
    });
  }

  const online = [];
  for (const row of directory) {
    if (row.id === me || friendIds.has(row.id) || incomingFrom.has(row.id) || !onlineAt(row, now)) continue;
    online.push({
      ...publicUser(row),
      request: outgoingTo.has(row.id) ? 'outgoing' : 'none',
    });
  }
  online.sort((a, b) => a.username.localeCompare(b.username));

  const outgoing = [];
  for (const row of outgoingRaw) {
    const to = byId.get(row.to_user_id);
    if (to) outgoing.push({ id: row.id, to: publicUser(to), online: onlineAt(to, now), createdAt: row.created_at });
  }

  const myRooms = rows(await db.from('room_members').select('room_id').eq('user_id', me));
  const roomsList = [];
  for (const r of myRooms) {
    const found = rows(await db.from('rooms').select('*').eq('id', r.room_id).limit(1));
    if (found.length === 1) {
      const room = found[0];
      const memberRows = rows(await db.from('room_members').select('user_id').eq('room_id', room.id));
      const memberNames = memberRows.map((m) => byId.get(m.user_id)?.username).filter(Boolean);
      roomsList.push({
        id: room.id,
        name: room.name,
        publicKey: room.public_key,
        keyAlgorithm: room.key_algorithm,
        memberUsernames: memberNames,
        membersCount: memberRows.length,
      });
    }
  }

  return json({
    friends,
    online,
    incoming,
    outgoing,
    rooms: roomsList,
    presenceWindowSeconds: Math.floor(PRESENCE_WINDOW_MS / 1000),
  });
}

async function requestFriend(db, request, userId) {
  const limit = await consume(db, 'friend_request', userId);
  if (!limit.allowed) return errorJson('rate_limited', 429, retryAfter(limit));

  const body = await readJson(request);
  const targetId = body?.userId;
  if (!isUuid(targetId) || targetId === userId) throw new AppError('invalid_input', 400);

  const target = await loadUser(db, targetId);
  if (!target) return errorJson('user_not_found', 404);
  if (await isFriend(db, userId, targetId)) return errorJson('already_friends', 409);

  const reverse = rows(await db.from('friend_requests')
    .select('id,status').eq('from_user_id', targetId).eq('to_user_id', userId).limit(1));
  if (reverse[0]?.status === 'pending') return errorJson('incoming_request_exists', 409);

  const existing = rows(await db.from('friend_requests')
    .select('id,status,created_at')
    .eq('from_user_id', userId).eq('to_user_id', targetId).limit(1));

  if (existing.length === 1) {
    const row = existing[0];
    if (row.status === 'pending') {
      return json({ request: { id: row.id, to: publicUser(target), createdAt: row.created_at } }, 200);
    }
    if (row.status === 'accepted') return errorJson('already_friends', 409);
    const now = new Date().toISOString();
    const revived = rows(await db.from('friend_requests')
      .update({ status: 'pending', responded_at: null, created_at: now })
      .eq('id', row.id).eq('status', 'declined').select('id,status,created_at'));
    if (revived.length === 1) {
      return json({ request: { id: row.id, to: publicUser(target), createdAt: now } }, 200);
    }
    const reread = rows(await db.from('friend_requests')
      .select('id,status,created_at').eq('id', row.id).limit(1));
    if (reread[0]?.status === 'pending') {
      return json({ request: { id: row.id, to: publicUser(target), createdAt: reread[0].created_at } }, 200);
    }
    return errorJson('request_conflict', 409);
  }

  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const inserted = rows(await db.from('friend_requests').insertIfAbsent({
    id, from_user_id: userId, to_user_id: targetId, status: 'pending', created_at: now, responded_at: null,
  }, { onConflict: 'from_user_id,to_user_id' }).select('id,status,created_at'));

  if (inserted.length === 1) {
    return json({ request: { id, to: publicUser(target), createdAt: now } }, 201);
  }
  const reread = rows(await db.from('friend_requests')
    .select('id,status,created_at')
    .eq('from_user_id', userId).eq('to_user_id', targetId).limit(1));
  if (reread[0]?.status === 'pending') {
    return json({ request: { id: reread[0].id, to: publicUser(target), createdAt: reread[0].created_at } }, 200);
  }
  return errorJson('request_conflict', 409);
}

async function ensureFriendship(db, userId, friendId) {
  const now = new Date().toISOString();
  rows(await db.from('friendships').insertIfAbsent({ user_id: userId, friend_id: friendId, created_at: now },
    { onConflict: 'user_id,friend_id' }).select('friend_id'));
  rows(await db.from('friendships').insertIfAbsent({ user_id: friendId, friend_id: userId, created_at: now },
    { onConflict: 'user_id,friend_id' }).select('friend_id'));
  const mine = rows(await db.from('friendships')
    .select('friend_id').eq('user_id', userId).eq('friend_id', friendId).limit(1));
  const theirs = rows(await db.from('friendships')
    .select('friend_id').eq('user_id', friendId).eq('friend_id', userId).limit(1));
  if (mine.length !== 1 || theirs.length !== 1) throw new AppError('friendship_unconfirmed', 503);
}

async function acceptFriend(db, request, userId) {
  const body = await readJson(request);
  const requestId = body?.requestId;
  if (!isUuid(requestId)) throw new AppError('invalid_input', 400);

  const found = rows(await db.from('friend_requests')
    .select('id,from_user_id,to_user_id,status').eq('id', requestId).limit(1));
  const row = found[0];
  if (!row || row.to_user_id !== userId) return errorJson('request_not_found', 404);
  if (row.status === 'declined') return errorJson('request_closed', 409);

  if (row.status === 'pending') {
    const accepted = rows(await db.from('friend_requests')
      .update({ status: 'accepted', responded_at: new Date().toISOString() })
      .eq('id', requestId).eq('to_user_id', userId).eq('status', 'pending')
      .select('id,status'));
    if (accepted.length !== 1) {
      const reread = rows(await db.from('friend_requests')
        .select('status').eq('id', requestId).eq('to_user_id', userId).limit(1));
      if (reread[0]?.status !== 'accepted') return errorJson('request_closed', 409);
    }
  }

  const from = await loadUser(db, row.from_user_id);
  if (!from) return errorJson('user_not_found', 404);
  await ensureFriendship(db, userId, row.from_user_id);
  const room = await ensureConversationRoom(db, userId, row.from_user_id);
  return json({
    friend: publicUser(from),
    room: room ? formatRoom(room, [userId, row.from_user_id]) : null,
  });
}

async function declineFriend(db, request, userId) {
  const body = await readJson(request);
  const requestId = body?.requestId;
  if (!isUuid(requestId)) throw new AppError('invalid_input', 400);

  const found = rows(await db.from('friend_requests')
    .select('id,to_user_id,status').eq('id', requestId).limit(1));
  const row = found[0];
  if (!row || row.to_user_id !== userId) return errorJson('request_not_found', 404);
  if (row.status === 'accepted') return errorJson('request_closed', 409);
  if (row.status === 'pending') {
    rows(await db.from('friend_requests')
      .update({ status: 'declined', responded_at: new Date().toISOString() })
      .eq('id', requestId).eq('to_user_id', userId).eq('status', 'pending')
      .select('id'));
  }
  return json({ ok: true });
}

async function createRoom(db, request, userId) {
  const body = await readJson(request);
  const name = typeof body?.name === 'string' && body.name.trim()
    ? body.name.trim().slice(0, 50)
    : `Room-${crypto.randomUUID().slice(0, 6)}`;
  let keys = body?.keys;
  if (!keys || typeof keys.publicKey !== 'string' || typeof keys.privateKey !== 'string') {
    keys = await generateServerRoomKeys();
  }
  const roomId = crypto.randomUUID();
  const now = new Date().toISOString();
  const inserted = rows(await db.from('rooms').insertIfAbsent({
    id: roomId,
    name,
    public_key: keys.publicKey,
    private_key: keys.privateKey,
    key_algorithm: keys.keyAlgorithm || 'AES-256-GCM',
    created_by: userId,
    created_at: now,
  }, { onConflict: 'id' }).select('id,name,public_key,private_key,key_algorithm,created_by,created_at'));
  const room = inserted[0] || (rows(await db.from('rooms').select('*').eq('id', roomId)))[0];
  await db.from('room_members').insertIfAbsent({ room_id: room.id, user_id: userId, joined_at: now }, { onConflict: 'room_id,user_id' });
  return json({ room: formatRoom(room, [userId]) }, 201);
}

async function joinRoom(db, request, userId) {
  const body = await readJson(request);
  let rawKey = typeof body?.privateKey === 'string' ? body.privateKey.trim() : '';
  let roomId = typeof body?.roomId === 'string' ? body.roomId.trim() : '';

  if (rawKey.startsWith('jn-room:')) {
    const parts = rawKey.split(':');
    if (parts.length >= 3) {
      roomId = parts[1];
      rawKey = parts.slice(2).join(':');
    }
  }

  let matchedRooms = [];
  if (isUuid(roomId)) {
    matchedRooms = rows(await db.from('rooms').select('*').eq('id', roomId).limit(1));
  } else if (rawKey) {
    matchedRooms = rows(await db.from('rooms').select('*').eq('private_key', rawKey).limit(1));
  }

  if (matchedRooms.length === 0) {
    return errorJson('room_not_found', 404);
  }

  const room = matchedRooms[0];
  if (rawKey && room.private_key !== rawKey) {
    return errorJson('invalid_room_key', 403);
  }

  const now = new Date().toISOString();
  await db.from('room_members').insertIfAbsent({
    room_id: room.id,
    user_id: userId,
    joined_at: now,
  }, { onConflict: 'room_id,user_id' });

  const members = rows(await db.from('room_members').select('user_id').eq('room_id', room.id));
  return json({ room: formatRoom(room, members.map((m) => m.user_id)) });
}

async function sendRelayPacket(db, request, userId) {
  const body = await readJson(request);
  const recipientId = body?.recipientId;
  const payload = body?.payload;
  const hopCount = Number(body?.hopCount) || 1;
  if (!isUuid(recipientId) || typeof payload !== 'string' || !payload) {
    throw new AppError('invalid_input', 400);
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await db.from('relay_packets').insertIfAbsent({
    id,
    recipient_id: recipientId,
    payload,
    hop_count: hopCount,
    created_at: now,
  }, { onConflict: 'id' });
  return json({ ok: true, packetId: id });
}

async function pollRelayPackets(db, request, userId) {
  const packets = rows(await db.from('relay_packets')
    .select('id,recipient_id,payload,hop_count,created_at')
    .eq('recipient_id', userId)
    .limit(50));

  if (packets.length > 0 && typeof db.from('relay_packets').delete === 'function') {
    for (const p of packets) {
      await db.from('relay_packets').delete().eq('id', p.id);
    }
  }
  return json({ packets });
}

async function readMessages(db, request, userId) {
  const url = new URL(request.url);
  const friendId = url.searchParams.get('friendId');
  const roomId = url.searchParams.get('roomId');

  let activeRoom = null;
  let targetFriend = null;

  if (isUuid(roomId)) {
    const membership = rows(await db.from('room_members')
      .select('room_id').eq('room_id', roomId).eq('user_id', userId).limit(1));
    if (membership.length === 0) return errorJson('room_forbidden', 403);

    const roomFound = rows(await db.from('rooms').select('*').eq('id', roomId).limit(1));
    if (roomFound.length === 0) return errorJson('room_not_found', 404);
    activeRoom = roomFound[0];
  } else if (isUuid(friendId) && friendId !== userId) {
    if (!(await isFriend(db, userId, friendId))) return errorJson('not_friends', 403);
    targetFriend = await loadUser(db, friendId);
    if (!targetFriend) return errorJson('user_not_found', 404);

    activeRoom = await ensureConversationRoom(db, userId, friendId);
  } else {
    throw new AppError('invalid_input', 400);
  }

  let list = [];
  if (activeRoom) {
    list = rows(await db.from('messages')
      .select('id,room_id,conversation_key,sender_id,recipient_id,body,nonce,hop_count,hop_trail,created_at')
      .eq('room_id', activeRoom.id)
      .order('created_at', { ascending: true })
      .limit(MESSAGE_PAGE_LIMIT));

    if (list.length === 0 && targetFriend) {
      const key = conversationKey(userId, friendId);
      list = rows(await db.from('messages')
        .select('id,room_id,conversation_key,sender_id,recipient_id,body,nonce,hop_count,hop_trail,created_at')
        .eq('conversation_key', key)
        .order('created_at', { ascending: true })
        .limit(MESSAGE_PAGE_LIMIT));
    }
  }

  const memberRows = activeRoom
    ? rows(await db.from('room_members').select('user_id').eq('room_id', activeRoom.id))
    : [];

  return json({
    friend: targetFriend ? {
      ...publicUser(targetFriend),
      publicKey: targetFriend.public_key,
      keyAlgorithm: targetFriend.key_algorithm,
      online: onlineAt(targetFriend),
    } : null,
    room: activeRoom ? formatRoom(activeRoom, memberRows.map((m) => m.user_id)) : null,
    messages: list.map(messageView),
  });
}

async function sendMessage(db, request, userId) {
  const limit = await consume(db, 'message', userId);
  if (!limit.allowed) return errorJson('rate_limited', 429, retryAfter(limit));

  const body = await readJson(request);
  const friendId = body?.friendId;
  const roomId = body?.roomId;
  const ciphertext = typeof body?.ciphertext === 'string' && body.ciphertext ? body.ciphertext : body?.text;
  const nonce = typeof body?.nonce === 'string' ? body.nonce : '';
  const hopCount = Number(body?.hopCount) || 1;
  const hopTrail = typeof body?.hopTrail === 'string' ? body.hopTrail : '';

  if (typeof ciphertext !== 'string' || !ciphertext.trim()) {
    throw new AppError('invalid_message', 400);
  }

  let activeRoom = null;
  let targetFriendId = null;

  if (isUuid(roomId)) {
    const membership = rows(await db.from('room_members')
      .select('room_id').eq('room_id', roomId).eq('user_id', userId).limit(1));
    if (membership.length === 0) return errorJson('room_forbidden', 403);
    const roomFound = rows(await db.from('rooms').select('*').eq('id', roomId).limit(1));
    if (roomFound.length === 0) return errorJson('room_not_found', 404);
    activeRoom = roomFound[0];
  } else if (isUuid(friendId) && friendId !== userId) {
    if (!(await isFriend(db, userId, friendId))) return errorJson('not_friends', 403);
    targetFriendId = friendId;
    activeRoom = await ensureConversationRoom(db, userId, friendId);
  } else {
    throw new AppError('invalid_input', 400);
  }

  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const convKey = targetFriendId ? conversationKey(userId, targetFriendId) : (activeRoom ? `room:${activeRoom.id}` : '');

  const inserted = rows(await db.from('messages').insertIfAbsent({
    id,
    conversation_key: convKey,
    room_id: activeRoom ? activeRoom.id : null,
    sender_id: userId,
    recipient_id: targetFriendId || null,
    body: ciphertext,
    nonce,
    hop_count: hopCount,
    hop_trail: hopTrail,
    created_at: createdAt,
  }, { onConflict: 'id' }).select('id,room_id,conversation_key,sender_id,recipient_id,body,nonce,hop_count,hop_trail,created_at'));

  if (inserted.length !== 1) throw new AppError('message_unconfirmed', 503);
  return json({ message: messageView(inserted[0]) }, 201);
}

async function route(db, request, origin) {
  requireTrustedOrigin(request, origin);
  const path = applicationPath(request);
  const method = request.method;

  if (path === '/api/health' && method === 'GET') return json({ ok: true });
  if (path === '/api/register' && method === 'POST') return register(db, request);
  if (path === '/api/login' && method === 'POST') return login(db, request);
  if (path === '/api/logout' && method === 'POST') return logout(db, request);

  const session = await requireSession(db, request);

  if (path === '/api/me' && method === 'GET') {
    return json({ user: selfView(await loadSelf(db, session.userId)) });
  }
  if (path === '/api/presence' && method === 'POST') {
    await touchPresence(db, session.userId);
    return json({ ok: true, now: new Date().toISOString() });
  }
  if (path === '/api/state' && method === 'GET') return state(db, request);
  if (path === '/api/friends/request' && method === 'POST') return requestFriend(db, request, session.userId);
  if (path === '/api/friends/accept' && method === 'POST') return acceptFriend(db, request, session.userId);
  if (path === '/api/friends/decline' && method === 'POST') return declineFriend(db, request, session.userId);
  if (path === '/api/messages' && method === 'GET') return readMessages(db, request, session.userId);
  if (path === '/api/messages' && method === 'POST') return sendMessage(db, request, session.userId);
  if (path === '/api/rooms/create' && method === 'POST') return createRoom(db, request, session.userId);
  if (path === '/api/rooms/join' && method === 'POST') return joinRoom(db, request, session.userId);
  if (path === '/api/relay/send' && method === 'POST') return sendRelayPacket(db, request, session.userId);
  if (path === '/api/relay/poll' && method === 'GET') return pollRelayPackets(db, request, session.userId);

  const known = new Set([
    '/api/me', '/api/presence', '/api/state', '/api/friends/request',
    '/api/friends/accept', '/api/friends/decline', '/api/messages',
    '/api/rooms/create', '/api/rooms/join', '/api/relay/send', '/api/relay/poll',
  ]);
  if (known.has(path)) throw new AppError('method_not_allowed', 405);
  throw new AppError('not_found', 404);
}

export function createApplication({ db, origin }) {
  return async function handle(ctx) {
    try {
      return await route(db, ctx.request, typeof origin === 'function' ? origin() : origin);
    } catch (error) {
      if (error instanceof SessionRequired) return unauthorized(error.state);
      if (error instanceof AppError) return errorJson(error.code, error.status);
      return errorJson('service_unavailable', 503);
    }
  };
}
