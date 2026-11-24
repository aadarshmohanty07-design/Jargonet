'use strict';

const API_PATH = '/functions/v1/app';
const STATE_POLL_MS = 4000;
const MESSAGE_POLL_MS = 2000;
const TOAST_MS = 2800;

const ERROR_MESSAGES = {
  invalid_username: 'Usernames need 3–32 characters: letters, numbers, underscores or hyphens.',
  invalid_password: 'Passwords need at least 8 characters.',
  invalid_credentials: 'That username and password don’t match.',
  username_taken: 'That username is already taken. Try another.',
  rate_limited: 'Too many attempts. Wait a moment and try again.',
  invalid_keys: 'Browser cannot create keypairs. Update Chrome, Edge, Firefox, or Safari.',
  invalid_input: 'Check the form and try again.',
  invalid_message: 'Messages can be up to 2,000 characters.',
  not_friends: 'You can only message someone after they accept your request.',
  already_friends: 'You are already connected with this person.',
  incoming_request_exists: 'They already sent you a request. Accept it from Requests.',
  user_not_found: 'That account is no longer available.',
  request_not_found: 'That request no longer exists.',
  request_closed: 'That request is no longer open.',
  request_conflict: 'That request changed in another tab. Refresh and try again.',
  login_required: 'Your session ended. Sign in again.',
  origin_forbidden: 'This request came from an unexpected origin.',
  application_auth_not_configured: 'Sign-in is not configured for this deployment yet.',
  logout_unconfirmed: 'Sign-out unconfirmed. Try again.',
  database_unavailable: 'The database is temporarily unavailable. Try again.',
  session_unavailable: 'Could not start a session. Try again.',
  friendship_unconfirmed: 'Could not confirm connection. Accept again.',
  message_unconfirmed: 'Message delivery unconfirmed. Check the conversation before resending.',
  registration_unconfirmed: 'Account creation unconfirmed. Try signing in with that username.',
  payload_too_large: 'That payload is too large.',
  network_error: 'Could not reach Jargonet. Check your connection and try again.',
  invalid_response: 'Jargonet returned an unexpected response.',
  service_unavailable: 'Jargonet is temporarily unavailable. Try again.',
  request_failed: 'That did not work. Try again.',
  room_not_found: 'That chatroom was not found. Check the private key.',
  invalid_room_key: 'Invalid chatroom private key.',
  room_forbidden: 'You must join this room to view its messages.',
  encryption_failed: 'Encryption failed. Web Crypto AES-GCM may be unsupported.',
};

const $ = (id) => document.getElementById(id);
const els = {
  boot: $('boot'),
  authView: $('auth-view'),
  appView: $('app-view'),
  modeSignin: $('mode-signin'),
  modeSignup: $('mode-signup'),
  authTitle: $('auth-title'),
  authSub: $('auth-sub'),
  authForm: $('auth-form'),
  username: $('username'),
  usernameHint: $('username-hint'),
  password: $('password'),
  passwordHint: $('password-hint'),
  togglePassword: $('toggle-password'),
  authError: $('auth-error'),
  authStatus: $('auth-status'),
  authSubmit: $('auth-submit'),
  switchCopy: $('switch-copy'),
  switchMode: $('switch-mode'),
  connection: $('connection'),
  connectionLabel: $('connection-label'),
  meHandle: $('me-handle'),
  logout: $('logout'),
  workspace: $('workspace'),
  meAvatar: $('me-avatar'),
  meName: $('me-name'),
  requestsSection: $('requests-section'),
  requestsCount: $('requests-count'),
  requestsList: $('requests-list'),
  chatList: $('chat-list'),
  chatsEmpty: $('chats-empty'),
  onlineCount: $('online-count'),
  onlineList: $('online-list'),
  onlineEmpty: $('online-empty'),
  welcome: $('welcome'),
  conversation: $('conversation'),
  back: $('back'),
  chatAvatar: $('chat-avatar'),
  chatName: $('chat-name'),
  chatStatus: $('chat-status'),
  chatSecurityTag: $('chat-security-tag'),
  chatRelayTag: $('chat-relay-tag'),
  tabChat: $('tab-chat'),
  tabDetails: $('tab-details'),
  panelChat: $('panel-chat'),
  panelDetails: $('panel-details'),
  messages: $('messages'),
  composer: $('composer'),
  messageInput: $('message-input'),
  send: $('send'),
  messageStatus: $('message-status'),
  meKeyAlgorithm: $('me-key-algorithm'),
  mePublicKey: $('me-public-key'),
  mePrivateKey: $('me-private-key'),
  meId: $('me-id'),
  roomKeyAlgorithm: $('room-key-algorithm'),
  roomPublicKey: $('room-public-key'),
  roomPrivateKey: $('room-private-key'),
  roomId: $('room-id'),
  roomMembersList: $('room-members-list'),
  activeHopsLabel: $('active-hops-label'),
  partnerKeyAlgorithm: $('partner-key-algorithm'),
  partnerNameInline: $('partner-name-inline'),
  partnerPublicKey: $('partner-public-key'),
  partnerId: $('partner-id'),
  btnOpenJoin: $('btn-open-join'),
  joinModal: $('join-modal'),
  btnCloseJoin: $('btn-close-join'),
  btnCancelJoin: $('btn-cancel-join'),
  joinForm: $('join-form'),
  joinPrivateKey: $('join-private-key'),
  joinError: $('join-error'),
  btnSubmitJoin: $('btn-submit-join'),
  toast: $('toast'),
};

const state = {
  me: null,
  friends: [],
  rooms: [],
  online: [],
  incoming: [],
  outgoing: [],
  selectedFriendId: null,
  selectedRoomId: null,
  friendDetail: null,
  roomDetail: null,
  roomKeys: new Map(),
  messages: [],
  authMode: 'signin',
  busy: false,
  sending: false,
  stateLoading: false,
  messageRequest: 0,
  selectedTab: 'chat',
  stateTimer: null,
  messageTimer: null,
  relayTimer: null,
  sidebarSignature: '',
  messageSignature: '',
  initialized: false,
  connected: true,
  toastTimer: null,
  requestBusy: new Set(),
  visibilityBound: false,
};

class ApiError extends Error {
  constructor(code, status = 0) {
    super(code);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

function messageFor(error) {
  if (error instanceof ApiError) return ERROR_MESSAGES[error.code] || ERROR_MESSAGES.request_failed;
  return ERROR_MESSAGES.request_failed;
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let response;
  try {
    response = await fetch(`${API_PATH}${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new ApiError('network_error');
  }
  if (response.redirected) throw new ApiError('invalid_response', response.status);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError('invalid_response', response.status);
  }
  if (!response.ok) {
    const code = typeof payload?.error === 'string' ? payload.error : 'request_failed';
    throw new ApiError(code, response.status);
  }
  return payload;
}

function isUser(value) {
  return Boolean(value) && typeof value.id === 'string' && typeof value.username === 'string';
}

function isSelf(value) {
  return isUser(value)
    && typeof value.publicKey === 'string'
    && typeof value.privateKey === 'string'
    && typeof value.keyAlgorithm === 'string';
}

function setConnection(live) {
  if (state.connected === live) return;
  state.connected = live;
  els.connection.dataset.state = live ? 'live' : 'reconnecting';
  els.connectionLabel.textContent = live ? 'Live' : 'Reconnecting…';
}

function setAvatar(element, username) {
  if (!element) return;
  const name = String(username ?? '');
  element.textContent = name.slice(0, 2);
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) {
    hash = ((hash << 5) - hash + name.charCodeAt(index)) | 0;
  }
  const hue = Math.abs(hash) % 360;
  element.style.background = `hsl(${hue} 32% 18%)`;
  element.style.color = `hsl(${hue} 68% 74%)`;
}

function avatarElement(username) {
  const element = document.createElement('div');
  element.className = 'avatar';
  element.setAttribute('aria-hidden', 'true');
  setAvatar(element, username);
  return element;
}

function dotElement(online) {
  const dot = document.createElement('span');
  dot.className = `dot${online ? ' online' : ''}`;
  dot.setAttribute('aria-hidden', 'true');
  return dot;
}

function showToast(message) {
  if (!message) return;
  els.toast.textContent = message;
  els.toast.classList.add('show');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => els.toast.classList.remove('show'), TOAST_MS);
}

function setAuthError(message) {
  els.authError.textContent = message || '';
  els.authError.hidden = !message;
}

function setAuthStatus(message) {
  els.authStatus.textContent = message || '';
}

function authSwitchText(text) {
  for (const node of els.switchCopy.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) { node.nodeValue = text; return; }
  }
}

function setMode(mode) {
  if (state.busy) return;
  state.authMode = mode;
  const signingIn = mode === 'signin';
  els.modeSignin.classList.toggle('is-active', signingIn);
  els.modeSignup.classList.toggle('is-active', !signingIn);
  els.modeSignin.setAttribute('aria-pressed', String(signingIn));
  els.modeSignup.setAttribute('aria-pressed', String(!signingIn));
  els.authTitle.textContent = signingIn ? 'Welcome back.' : 'Create your account.';
  els.authSub.textContent = signingIn
    ? 'Enter your username and password.'
    : 'Pick a username and password. Keys stay in your browser.';
  els.usernameHint.hidden = signingIn;
  els.passwordHint.hidden = signingIn;
  els.password.autocomplete = signingIn ? 'current-password' : 'new-password';
  els.authSubmit.textContent = signingIn ? 'Sign in' : 'Create account';
  authSwitchText(signingIn ? 'New to Jargonet? ' : 'Already have an account? ');
  els.switchMode.textContent = signingIn ? 'Create an account' : 'Sign in';
  els.password.value = '';
  els.password.type = 'password';
  els.togglePassword.textContent = 'Show';
  els.togglePassword.setAttribute('aria-pressed', 'false');
  setAuthError('');
  setAuthStatus('');
}

function setAuthBusy(busy, status = '') {
  state.busy = busy;
  els.authForm.setAttribute('aria-busy', String(busy));
  for (const control of [els.username, els.password, els.authSubmit, els.modeSignin, els.modeSignup, els.togglePassword]) {
    control.disabled = busy;
  }
  els.authSubmit.textContent = busy ? (state.authMode === 'signin' ? 'Signing in…' : 'Creating account…') : (state.authMode === 'signin' ? 'Sign in' : 'Create account');
  setAuthStatus(status);
}

function resetSensitiveView() {
  els.mePublicKey.textContent = '';
  // The details panel no longer shows the private key or the other party's
  // key, so these nodes can be absent. They are still cleared when present.
  if (els.mePrivateKey) els.mePrivateKey.textContent = '';
  if (els.partnerPublicKey) els.partnerPublicKey.textContent = '';
  els.meId.textContent = '';
  els.meKeyAlgorithm.textContent = '';
  if (els.partnerId) els.partnerId.textContent = '';
  if (els.partnerKeyAlgorithm) els.partnerKeyAlgorithm.textContent = '';
  if (els.partnerNameInline) els.partnerNameInline.textContent = '';
  if (els.roomPublicKey) els.roomPublicKey.textContent = '';
  if (els.roomPrivateKey) els.roomPrivateKey.textContent = '';
  if (els.roomId) els.roomId.textContent = '';
  if (els.roomMembersList) els.roomMembersList.replaceChildren();
  els.chatName.textContent = '';
  els.meHandle.textContent = '';
  els.meName.textContent = '';
  els.meAvatar.textContent = '';
  els.chatAvatar.textContent = '';
  els.messages.replaceChildren();
  els.messageStatus.textContent = '';
  els.requestsList.replaceChildren();
  els.chatList.replaceChildren();
  els.onlineList.replaceChildren();
  els.requestsSection.hidden = true;
  state.me = null;
  state.friends = [];
  state.rooms = [];
  state.online = [];
  state.incoming = [];
  state.outgoing = [];
  state.selectedFriendId = null;
  state.selectedRoomId = null;
  state.friendDetail = null;
  state.roomDetail = null;
  state.roomKeys.clear();
  state.messages = [];
  state.initialized = false;
  state.sidebarSignature = '';
  state.messageSignature = '';
  state.requestBusy.clear();
  state.sending = false;
  state.messageRequest += 1;
}

function stopPolling() {
  clearInterval(state.stateTimer);
  clearInterval(state.messageTimer);
  clearInterval(state.relayTimer);
  state.stateTimer = null;
  state.messageTimer = null;
  state.relayTimer = null;
}

function showAuth(message = '') {
  stopPolling();
  resetSensitiveView();
  els.boot.hidden = true;
  els.appView.hidden = true;
  els.authView.hidden = false;
  document.title = 'Jargonet';
  state.authMode = 'signin';
  setMode('signin');
  setAuthBusy(false);
  els.username.value = '';
  els.password.value = '';
  setAuthError(message);
  window.scrollTo(0, 0);
  requestAnimationFrame(() => els.username.focus());
}

function showApp() {
  els.boot.hidden = true;
  els.authView.hidden = true;
  els.appView.hidden = false;
  window.scrollTo(0, 0);
  document.title = `@${state.me.username} — Jargonet`;
  els.meHandle.textContent = `@${state.me.username}`;
  els.meName.textContent = `@${state.me.username}`;
  setAvatar(els.meAvatar, state.me.username);
  els.meKeyAlgorithm.textContent = state.me.keyAlgorithm;
  els.mePublicKey.textContent = state.me.publicKey;
  if (els.mePrivateKey) els.mePrivateKey.textContent = state.me.privateKey;
  els.meId.textContent = state.me.id;
  els.welcome.hidden = false;
  els.conversation.hidden = true;
  els.workspace.classList.remove('chat-open');
  switchTab('chat');
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveRoomCryptoKey(base64Secret) {
  const rawBytes = base64ToBytes(base64Secret);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    rawBytes,
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  const salt = new TextEncoder().encode('jargonet-mesh-v1');
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptRoomMessage(text, base64Secret) {
  try {
    const key = await deriveRoomCryptoKey(base64Secret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded,
    );
    return {
      ciphertext: bytesToBase64(new Uint8Array(encrypted)),
      nonce: bytesToBase64(iv),
    };
  } catch (err) {
    console.error('Encryption failed:', err);
    throw new ApiError('encryption_failed');
  }
}

async function decryptRoomMessage(ciphertextB64, nonceB64, base64Secret) {
  if (!ciphertextB64 || !nonceB64 || !base64Secret) return ciphertextB64;
  try {
    const key = await deriveRoomCryptoKey(base64Secret);
    const iv = base64ToBytes(nonceB64);
    const data = base64ToBytes(ciphertextB64);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data,
    );
    return new TextDecoder().decode(decrypted);
  } catch {
    return ciphertextB64;
  }
}

function buildPeerHoppingRoute(destinationName) {
  const candidates = state.online.filter((p) => p.username !== state.me?.username && p.username !== destinationName);
  const shuffled = [...candidates].sort(() => Math.random() - 0.5);
  const relays = shuffled.slice(0, Math.min(3, shuffled.length));
  const hopNodes = [state.me?.username ? `@${state.me.username}` : 'you', ...relays.map((r) => `@${r.username}`), destinationName ? (destinationName.startsWith('@') ? destinationName : `@${destinationName}`) : 'peer'];
  const hopTrail = hopNodes.join(' → ');
  return {
    relays,
    hopCount: relays.length + 1,
    hopTrail,
  };
}

async function pollAndProcessRelays() {
  if (!state.me) return;
  try {
    const data = await api('/api/relay/poll');
    if (!Array.isArray(data?.packets) || data.packets.length === 0) return;
    for (const packet of data.packets) {
      try {
        const decoded = JSON.parse(packet.payload);
        if (decoded.nextRecipientId && decoded.innerPayload) {
          await api('/api/relay/send', {
            method: 'POST',
            body: {
              recipientId: decoded.nextRecipientId,
              payload: decoded.innerPayload,
              hopCount: (packet.hop_count || 1) + 1,
            },
          });
        }
      } catch {
        // Blind envelope
      }
    }
  } catch {
    // Silent fail
  }
}

function updateChatHeader() {
  if (state.selectedRoomId && state.roomDetail) {
    els.chatName.textContent = `#${state.roomDetail.name}`;
    setAvatar(els.chatAvatar, state.roomDetail.name);
    els.chatStatus.replaceChildren(dotElement(true), document.createTextNode('Group Chat'));
    if (els.chatSecurityTag) els.chatSecurityTag.textContent = '🔒 AES-256-GCM';
    if (els.chatRelayTag) {
      const hopText = state.online.length > 2 ? '3 Hops Active' : (state.online.length > 0 ? '1-2 Hops' : 'Direct E2EE');
      els.chatRelayTag.textContent = `⚡ ${hopText}`;
    }
    return;
  }
  if (!state.selectedFriendId) return;
  const friend = state.friendDetail?.id === state.selectedFriendId
    ? state.friendDetail
    : state.friends.find((item) => item.id === state.selectedFriendId);
  if (!friend) return;
  els.chatName.textContent = `@${friend.username}`;
  setAvatar(els.chatAvatar, friend.username);
  els.chatStatus.replaceChildren(dotElement(Boolean(friend.online)), document.createTextNode(friend.online ? 'Online now' : 'Offline'));
  if (els.chatSecurityTag) els.chatSecurityTag.textContent = '🔒 AES-256-GCM';
  if (els.chatRelayTag) {
    const hopText = state.online.length > 2 ? '3 Hops Active' : (state.online.length > 0 ? '1-2 Hops' : 'Direct E2EE');
    els.chatRelayTag.textContent = `⚡ ${hopText}`;
  }
}

function renderRequests() {
  els.requestsSection.hidden = state.incoming.length === 0;
  els.requestsCount.textContent = String(state.incoming.length);
  els.requestsList.replaceChildren();
  for (const request of state.incoming) {
    const wrapper = document.createElement('div');
    wrapper.className = 'request';
    const who = document.createElement('div');
    who.className = 'request-who';
    who.append(avatarElement(request.from.username));
    const copy = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = `@${request.from.username}`;
    const sub = document.createElement('span');
    sub.append(dotElement(Boolean(request.online)), document.createTextNode('wants to connect'));
    copy.append(name, sub);
    who.append(copy);

    const actions = document.createElement('div');
    actions.className = 'request-actions';
    const accept = document.createElement('button');
    accept.className = 'button small';
    accept.type = 'button';
    accept.textContent = 'Accept';
    accept.setAttribute('aria-label', `Accept request from ${request.from.username}`);
    const ignore = document.createElement('button');
    ignore.className = 'link-button';
    ignore.type = 'button';
    ignore.textContent = 'Ignore';
    ignore.setAttribute('aria-label', `Ignore request from ${request.from.username}`);
    if (state.requestBusy.has(request.id)) {
      accept.disabled = true;
      ignore.disabled = true;
    }
    accept.addEventListener('click', () => void acceptRequest(request.id, accept));
    ignore.addEventListener('click', () => void declineRequest(request.id, ignore));
    actions.append(accept, ignore);
    wrapper.append(who, actions);
    els.requestsList.append(wrapper);
  }
}

function renderChats() {
  els.chatList.replaceChildren();
  for (const friend of state.friends) {
    const button = document.createElement('button');
    button.type = 'button';
    const isActive = friend.id === state.selectedFriendId;
    button.className = `person${isActive ? ' is-active' : ''}`;
    if (isActive) button.setAttribute('aria-current', 'true');
    button.append(avatarElement(friend.username));
    const copy = document.createElement('div');
    copy.className = 'person-main';
    const name = document.createElement('strong');
    name.textContent = `@${friend.username}`;
    const status = document.createElement('span');
    status.append(dotElement(Boolean(friend.online)), document.createTextNode(friend.online ? 'Online' : 'Offline'));
    copy.append(name, status);
    button.append(copy);
    button.addEventListener('click', () => void selectFriend(friend.id));
    els.chatList.append(button);
  }
  const customRooms = state.rooms.filter((r) => !r.name.startsWith('chat:'));
  for (const room of customRooms) {
    const button = document.createElement('button');
    button.type = 'button';
    const isActive = room.id === state.selectedRoomId;
    button.className = `person${isActive ? ' is-active' : ''}`;
    if (isActive) button.setAttribute('aria-current', 'true');
    button.append(avatarElement(room.name));
    const copy = document.createElement('div');
    copy.className = 'person-main';
    const name = document.createElement('strong');
    name.textContent = `#${room.name}`;
    const status = document.createElement('span');
    status.textContent = `${room.membersCount || 1} participant${room.membersCount === 1 ? '' : 's'}`;
    copy.append(name, status);
    button.append(copy);
    button.addEventListener('click', () => void selectRoom(room.id));
    els.chatList.append(button);
  }
  els.chatsEmpty.hidden = (state.friends.length + customRooms.length) > 0;
}

function renderOnline() {
  els.onlineList.replaceChildren();
  els.onlineCount.textContent = String(state.online.length);
  els.onlineEmpty.hidden = state.online.length > 0;
  for (const person of state.online) {
    const row = document.createElement('div');
    row.className = 'person';
    row.append(avatarElement(person.username));
    const copy = document.createElement('div');
    copy.className = 'person-main';
    const name = document.createElement('strong');
    name.textContent = `@${person.username}`;
    const status = document.createElement('span');
    status.append(dotElement(true), document.createTextNode('Online now'));
    copy.append(name, status);
    row.append(copy);

    if (person.request === 'outgoing') {
      const tag = document.createElement('span');
      tag.className = 'tag';
      tag.textContent = 'Requested';
      row.append(tag);
    } else {
      const add = document.createElement('button');
      add.type = 'button';
      add.className = 'row-action';
      add.textContent = 'Add';
      add.setAttribute('aria-label', `Send a chat request to ${person.username}`);
      add.addEventListener('click', () => void sendRequest(person.id, person.username, add));
      row.append(add);
    }
    els.onlineList.append(row);
  }
}

function renderSidebar(force = false) {
  const signature = JSON.stringify({
    friends: state.friends,
    rooms: state.rooms,
    online: state.online,
    incoming: state.incoming,
    selectedFriend: state.selectedFriendId,
    selectedRoom: state.selectedRoomId,
  });
  if (!force && signature === state.sidebarSignature) return;
  state.sidebarSignature = signature;
  renderRequests();
  renderChats();
  renderOnline();
}

async function refreshState(quiet = false) {
  if (!state.me || state.stateLoading) return;
  state.stateLoading = true;
  const previousFriends = new Set(state.friends.map((friend) => friend.id));
  const previousIncoming = new Set(state.incoming.map((request) => request.id));
  try {
    const data = await api('/api/state');
    const valid = ['friends', 'online', 'incoming', 'outgoing'].every((key) => Array.isArray(data?.[key]));
    if (!valid) throw new ApiError('invalid_response');
    state.friends = data.friends.filter(isUser).map((friend) => ({ ...friend, online: Boolean(friend.online) }));
    state.online = data.online.filter(isUser);
    state.incoming = data.incoming.filter((request) => isUser(request?.from));
    state.outgoing = data.outgoing.filter((request) => isUser(request?.to));
    if (Array.isArray(data?.rooms)) {
      state.rooms = data.rooms;
      for (const r of data.rooms) {
        state.roomKeys.set(r.id, r);
      }
    }
    setConnection(true);
    renderSidebar();
    if (state.selectedFriendId) {
      const selected = state.friends.find((friend) => friend.id === state.selectedFriendId);
      if (selected) updateChatHeader();
      else closeConversation();
    } else if (state.selectedRoomId) {
      const selected = state.rooms.find((r) => r.id === state.selectedRoomId);
      if (selected) {
        state.roomDetail = selected;
        updateChatHeader();
      }
    }
    if (!state.initialized) {
      state.initialized = true;
    } else {
      const newFriends = state.friends.filter((friend) => !previousFriends.has(friend.id));
      const newRequests = state.incoming.filter((request) => !previousIncoming.has(request.id));
      if (newFriends.length && !state.selectedFriendId && !state.selectedRoomId) {
        showToast(`You’re connected with @${newFriends[0].username}.`);
        void selectFriend(newFriends[0].id);
      } else if (newFriends.length) {
        showToast(`You’re connected with @${newFriends[0].username}.`);
      }
      if (newRequests.length) showToast(`New request from @${newRequests[0].from.username}.`);
    }
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      onSessionLost();
      return;
    }
    setConnection(false);
    if (!quiet && !(error instanceof ApiError && error.status === 0)) showToast(messageFor(error));
  } finally {
    state.stateLoading = false;
  }
}

async function acceptRequest(requestId, button) {
  if (state.requestBusy.has(requestId)) return;
  state.requestBusy.add(requestId);
  button.disabled = true;
  try {
    const data = await api('/api/friends/accept', { method: 'POST', body: { requestId } });
    if (!isUser(data?.friend)) throw new ApiError('invalid_response');
    if (data?.room) {
      state.roomDetail = data.room;
      state.roomKeys.set(data.room.id, data.room);
    }
    showToast(`You’re connected with @${data.friend.username}.`);
    await refreshState(true);
    await selectFriend(data.friend.id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) onSessionLost();
    else showToast(messageFor(error));
  } finally {
    state.requestBusy.delete(requestId);
    renderSidebar(true);
  }
}

async function declineRequest(requestId, button) {
  if (state.requestBusy.has(requestId)) return;
  state.requestBusy.add(requestId);
  button.disabled = true;
  try {
    await api('/api/friends/decline', { method: 'POST', body: { requestId } });
    await refreshState(true);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) onSessionLost();
    else showToast(messageFor(error));
  } finally {
    state.requestBusy.delete(requestId);
    renderSidebar(true);
  }
}

async function sendRequest(userId, username, button) {
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = 'Sending';
  try {
    await api('/api/friends/request', { method: 'POST', body: { userId } });
    showToast(`Request sent to @${username}.`);
    await refreshState(true);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) onSessionLost();
    else showToast(messageFor(error));
    button.disabled = false;
    button.textContent = 'Add';
  }
}

function closeConversation() {
  state.selectedFriendId = null;
  state.selectedRoomId = null;
  state.friendDetail = null;
  state.roomDetail = null;
  state.messages = [];
  state.messageSignature = '';
  state.messageRequest += 1;
  els.conversation.hidden = true;
  els.welcome.hidden = false;
  els.workspace.classList.remove('chat-open');
  els.messageStatus.textContent = '';
  renderSidebar();
}

async function selectFriend(friendId) {
  const friend = state.friends.find((item) => item.id === friendId);
  if (!friend) return;
  state.selectedFriendId = friendId;
  state.selectedRoomId = null;
  state.friendDetail = { ...friend, publicKey: '', keyAlgorithm: '' };
  state.messages = [];
  state.messageSignature = '';
  state.messageRequest += 1;
  els.welcome.hidden = true;
  els.conversation.hidden = false;
  els.workspace.classList.add('chat-open');
  els.messageInput.value = '';
  els.messageStatus.textContent = '';
  autoGrow();
  updateComposer();
  updateChatHeader();
  switchTab('chat');
  renderSidebar();
  renderDetails();
  renderMessages(true);
  await loadMessages(false);
}

async function selectRoom(roomId) {
  const room = state.rooms.find((item) => item.id === roomId);
  if (!room) return;
  state.selectedRoomId = roomId;
  state.selectedFriendId = null;
  state.friendDetail = null;
  state.roomDetail = room;
  state.messages = [];
  state.messageSignature = '';
  state.messageRequest += 1;
  els.welcome.hidden = true;
  els.conversation.hidden = false;
  els.workspace.classList.add('chat-open');
  els.messageInput.value = '';
  els.messageStatus.textContent = '';
  autoGrow();
  updateComposer();
  updateChatHeader();
  switchTab('chat');
  renderSidebar();
  renderDetails();
  renderMessages(true);
  await loadMessages(false);
}

async function loadMessages(quiet) {
  const friendId = state.selectedFriendId;
  const roomId = state.selectedRoomId;
  if (!friendId && !roomId) return;
  const request = ++state.messageRequest;
  try {
    const url = roomId
      ? `/api/messages?roomId=${encodeURIComponent(roomId)}`
      : `/api/messages?friendId=${encodeURIComponent(friendId)}`;
    const data = await api(url);
    if (request !== state.messageRequest) return;
    if (roomId && state.selectedRoomId !== roomId) return;
    if (friendId && state.selectedFriendId !== friendId) return;

    if (data?.room) {
      state.roomDetail = data.room;
      state.roomKeys.set(data.room.id, data.room);
    }
    if (data?.friend) {
      state.friendDetail = data.friend;
    }

    const rawMessages = Array.isArray(data.messages) ? data.messages : [];
    const decryptedMessages = [];
    const roomKey = state.roomDetail?.privateKey;

    for (const msg of rawMessages) {
      if (!msg || typeof msg.id !== 'string') continue;
      let text = msg.text || msg.ciphertext || '';
      if (roomKey && msg.ciphertext && msg.nonce) {
        text = await decryptRoomMessage(msg.ciphertext, msg.nonce, roomKey);
      }
      decryptedMessages.push({
        ...msg,
        text,
      });
    }

    state.messages = decryptedMessages;
    if (state.friendDetail && Boolean(state.friendDetail.online) !== Boolean(data.friend?.online)) {
      state.friendDetail.online = Boolean(data.friend?.online);
      renderSidebar(true);
    }
    updateChatHeader();
    renderDetails();
    renderMessages();
    setConnection(true);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      onSessionLost();
      return;
    }
    if (!quiet) els.messageStatus.textContent = messageFor(error);
  }
}

function isNearBottom() {
  const element = els.messages;
  return element.scrollHeight - element.scrollTop - element.clientHeight < 90;
}

function dayLabel(iso) {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return '';
  const today = new Date();
  const sameDay = date.getFullYear() === today.getFullYear()
    && date.getMonth() === today.getMonth() && date.getDate() === today.getDate();
  if (sameDay) return 'Today';
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
}

function timeLabel(iso) {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return '';
  return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

function renderMessages(force = false) {
  const activeChatId = state.selectedFriendId || state.selectedRoomId;
  if (!activeChatId) {
    els.messages.replaceChildren();
    return;
  }
  const signature = `${activeChatId}:${state.messages.map((message) => message.id).join('|')}`;
  if (!force && signature === state.messageSignature) return;
  const stick = isNearBottom() || force;
  state.messageSignature = signature;
  const fragment = document.createDocumentFragment();
  if (state.messages.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'messages-empty';
    const title = document.createElement('strong');
    title.textContent = 'No messages yet.';
    const peerName = state.friendDetail ? `@${state.friendDetail.username}` : (state.roomDetail ? `#${state.roomDetail.name}` : 'the room');
    empty.append(title, document.createTextNode(`Say hello to ${peerName}. Messages are encrypted with the room private key.`));
    fragment.append(empty);
  } else {
    let lastDay = '';
    for (const message of state.messages) {
      const day = dayLabel(message.createdAt);
      if (day && day !== lastDay) {
        lastDay = day;
        const mark = document.createElement('div');
        mark.className = 'day-mark';
        mark.textContent = day;
        fragment.append(mark);
      }
      const own = message.senderId === state.me?.id;
      const article = document.createElement('article');
      article.className = `message ${own ? 'own' : 'other'}`;
      const meta = document.createElement('div');
      meta.className = 'message-meta';
      const who = document.createElement('span');
      who.textContent = own ? 'You' : (state.friendDetail ? `@${state.friendDetail.username}` : 'Member');
      const time = document.createElement('time');
      time.dateTime = message.createdAt;
      time.textContent = timeLabel(message.createdAt);
      meta.append(who, time);

      const hopTag = document.createElement('span');
      hopTag.className = 'message-hop-tag';
      hopTag.title = message.hopTrail ? `Relayed via: ${message.hopTrail}` : 'End-to-end encrypted packet';
      hopTag.textContent = message.hopCount > 1 ? `🔒 ${message.hopCount} hops` : '🔒 E2EE';
      meta.append(hopTag);

      const bubble = document.createElement('p');
      bubble.className = 'bubble';
      bubble.textContent = message.text;
      article.append(meta, bubble);
      fragment.append(article);
    }
  }
  els.messages.replaceChildren(fragment);
  if (stick) requestAnimationFrame(() => { els.messages.scrollTop = els.messages.scrollHeight; });
}

function renderDetails() {
  if (!state.me) return;
  els.meKeyAlgorithm.textContent = state.me.keyAlgorithm;
  els.mePublicKey.textContent = state.me.publicKey;
  els.meId.textContent = state.me.id;

  const room = state.roomDetail;
  if (els.roomPublicKey) els.roomPublicKey.textContent = room?.publicKey || 'Loading…';
  if (els.roomPrivateKey) els.roomPrivateKey.textContent = room?.privateKey || 'Loading…';
  if (els.roomId) els.roomId.textContent = room?.id || (state.selectedFriendId ? `chat:${state.selectedFriendId}` : '-');
  if (els.roomKeyAlgorithm) els.roomKeyAlgorithm.textContent = room?.keyAlgorithm || 'AES-256-GCM';

  if (els.activeHopsLabel) {
    els.activeHopsLabel.textContent = state.online.length >= 2
      ? `Active (${Math.min(3, state.online.length)} random peer hops)`
      : (state.online.length === 1 ? 'Active (1 peer hop)' : 'Direct Encrypted (Peer mesh ready)');
  }

  if (els.roomMembersList) {
    els.roomMembersList.replaceChildren();
    const members = room?.memberUsernames || (state.friendDetail ? [state.me.username, state.friendDetail.username] : [state.me.username]);
    for (const member of members) {
      const chip = document.createElement('span');
      chip.className = 'member-chip';
      chip.textContent = `@${member}`;
      els.roomMembersList.append(chip);
    }
  }

  for (const button of document.querySelectorAll('[data-copy="room-public-key"], [data-copy="room-private-key"]')) {
    button.disabled = !room?.privateKey;
  }
}

function switchTab(tab) {
  const chat = tab === 'chat';
  state.selectedTab = tab;
  els.tabChat.classList.toggle('is-active', chat);
  els.tabDetails.classList.toggle('is-active', !chat);
  els.tabChat.setAttribute('aria-selected', String(chat));
  els.tabDetails.setAttribute('aria-selected', String(!chat));
  els.panelChat.hidden = !chat;
  els.panelDetails.hidden = chat;
  if (!chat) renderDetails();
}

function updateComposer() {
  const text = els.messageInput.value.trim();
  const hasTarget = Boolean(state.selectedFriendId || state.selectedRoomId);
  els.send.disabled = state.sending || !text || !hasTarget;
  els.messageInput.disabled = state.sending || !hasTarget;
}

function autoGrow() {
  els.messageInput.style.height = 'auto';
  els.messageInput.style.height = `${Math.min(els.messageInput.scrollHeight, 160)}px`;
}

async function sendMessage() {
  const text = els.messageInput.value.trim();
  const friendId = state.selectedFriendId;
  const roomId = state.selectedRoomId || state.roomDetail?.id;
  if (!text || (!friendId && !roomId) || state.sending) return;
  state.sending = true;
  updateComposer();
  els.messageStatus.textContent = '';
  try {
    const roomKey = state.roomDetail?.privateKey;
    let ciphertext = text;
    let nonce = '';
    if (roomKey) {
      const encrypted = await encryptRoomMessage(text, roomKey);
      ciphertext = encrypted.ciphertext;
      nonce = encrypted.nonce;
    }

    const destName = state.friendDetail?.username || state.roomDetail?.name || 'peer';
    const route = buildPeerHoppingRoute(destName);

    const body = {
      friendId: friendId || undefined,
      roomId: roomId || undefined,
      ciphertext,
      nonce,
      hopCount: route.hopCount,
      hopTrail: route.hopTrail,
    };

    if (route.relays.length > 0) {
      const firstRelay = route.relays[0];
      try {
        await api('/api/relay/send', {
          method: 'POST',
          body: {
            recipientId: firstRelay.id,
            payload: JSON.stringify({
              nextRecipientId: route.relays[1]?.id || (friendId || roomId),
              innerPayload: ciphertext,
            }),
            hopCount: 1,
          },
        });
      } catch {
        // Fallback
      }
    }

    const data = await api('/api/messages', { method: 'POST', body });
    if (data?.message && typeof data.message.id === 'string') {
      const returnedMsg = {
        ...data.message,
        text,
      };
      if (!state.messages.some((message) => message.id === returnedMsg.id)) {
        state.messages.push(returnedMsg);
      }
      els.messageInput.value = '';
      autoGrow();
      renderMessages(true);
    }
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) onSessionLost();
    else els.messageStatus.textContent = messageFor(error);
  } finally {
    state.sending = false;
    updateComposer();
    if (state.selectedFriendId || state.selectedRoomId) els.messageInput.focus();
  }
}

async function copyText(text) {
  if (!text) return false;
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return true;
  }
  const field = document.createElement('textarea');
  field.value = text;
  field.setAttribute('readonly', '');
  field.style.position = 'fixed';
  field.style.left = '-9999px';
  document.body.append(field);
  field.select();
  const copied = document.execCommand('copy');
  field.remove();
  return copied;
}

async function copyInvite() {
  try {
    const copied = await copyText(`${location.origin}${location.pathname}`);
    if (copied) showToast('Invite link copied. Send it to your friend.');
    else showToast('Could not copy the link. Copy the address from the browser.');
  } catch {
    showToast('Could not copy the link. Copy the address from the browser.');
  }
}

async function generateIdentityKeys() {
  if (!globalThis.crypto?.subtle) throw new ApiError('invalid_keys');
  const algorithms = [
    { name: 'X25519', params: { name: 'X25519' }, usages: ['deriveBits'] },
    { name: 'Ed25519', params: { name: 'Ed25519' }, usages: ['sign', 'verify'] },
  ];
  for (const algorithm of algorithms) {
    try {
      const pair = await crypto.subtle.generateKey(algorithm.params, true, algorithm.usages);
      const publicKey = await crypto.subtle.exportKey('raw', pair.publicKey);
      const privateKey = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
      return {
        publicKey: bytesToBase64(new Uint8Array(publicKey)),
        privateKey: bytesToBase64(new Uint8Array(privateKey)),
        keyAlgorithm: algorithm.name,
      };
    } catch {
      // Try the next supported curve.
    }
  }
  throw new ApiError('invalid_keys');
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function enterApp() {
  if (!state.me) return;
  showApp();
  await refreshState(true);
  if (!state.me) return;
  startPolling();
}

async function loadProfileAndEnter() {
  const profile = await api('/api/me');
  if (!isSelf(profile?.user)) throw new ApiError('invalid_response');
  state.me = profile.user;
  await enterApp();
}

async function loadSession() {
  try {
    const profile = await api('/api/me');
    if (!isSelf(profile?.user)) throw new ApiError('invalid_response');
    state.me = profile.user;
    await enterApp();
  } catch (error) {
    showAuth(error instanceof ApiError && error.status === 401 ? '' : messageFor(error));
  } finally {
    els.boot.hidden = true;
  }
}

function onSessionLost() {
  showAuth('Your session ended. Sign in again.');
}

function openJoinModal() {
  if (!els.joinModal) return;
  els.joinModal.hidden = false;
  els.joinPrivateKey.value = '';
  els.joinError.hidden = true;
  els.joinError.textContent = '';
  els.joinPrivateKey.focus();
}

function closeJoinModal() {
  if (!els.joinModal) return;
  els.joinModal.hidden = true;
  els.joinError.hidden = true;
  els.joinPrivateKey.value = '';
}

async function submitJoinRoom(event) {
  event.preventDefault();
  const rawKey = els.joinPrivateKey.value.trim();
  if (!rawKey) {
    els.joinError.textContent = 'Paste a chatroom private key.';
    els.joinError.hidden = false;
    return;
  }
  els.btnSubmitJoin.disabled = true;
  els.joinError.hidden = true;
  try {
    const data = await api('/api/rooms/join', {
      method: 'POST',
      body: { privateKey: rawKey },
    });
    if (!data?.room) throw new ApiError('room_not_found');
    closeJoinModal();
    showToast(`Joined chatroom #${data.room.name}`);
    await refreshState(true);
    await selectRoom(data.room.id);
  } catch (error) {
    els.joinError.textContent = messageFor(error);
    els.joinError.hidden = false;
  } finally {
    els.btnSubmitJoin.disabled = false;
  }
}

function startPolling() {
  stopPolling();
  const tick = async () => {
    if (!state.me || state.stateLoading) return;
    try {
      await Promise.all([
        api('/api/presence', { method: 'POST' }),
        refreshState(true),
        pollAndProcessRelays(),
      ]);
      setConnection(true);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) onSessionLost();
      else setConnection(false);
    }
  };
  state.stateTimer = setInterval(tick, STATE_POLL_MS);
  state.messageTimer = setInterval(() => { void loadMessages(true); }, MESSAGE_POLL_MS);
  state.relayTimer = setInterval(() => { void pollAndProcessRelays(); }, 3000);
  if (!state.visibilityBound) {
    state.visibilityBound = true;
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'visible' || !state.me) return;
      void tick();
      if (state.selectedFriendId || state.selectedRoomId) void loadMessages(true);
    });
  }
}

async function submitAuth(event) {
  event.preventDefault();
  if (state.busy) return;
  const username = els.username.value.trim();
  const password = els.password.value;
  if (!username || !password) {
    setAuthError('Enter a username and password.');
    return;
  }
  if (state.authMode === 'signup' && [...password].length < 8) {
    setAuthError(ERROR_MESSAGES.invalid_password);
    return;
  }
  setAuthError('');
  els.password.value = '';
  setAuthBusy(true, state.authMode === 'signup' ? 'Creating your identity keys…' : 'Signing in…');
  try {
    if (state.authMode === 'signup') {
      const keys = await generateIdentityKeys();
      setAuthStatus('Creating your account…');
      await api('/api/register', { method: 'POST', body: { username, password, ...keys } });
    } else {
      await api('/api/login', { method: 'POST', body: { username, password } });
    }
    await loadProfileAndEnter();
  } catch (error) {
    setAuthError(messageFor(error));
  } finally {
    setAuthBusy(false);
  }
}

async function logout() {
  els.logout.disabled = true;
  try {
    await api('/api/logout', { method: 'POST' });
  } catch (error) {
    showToast(messageFor(error));
    els.logout.disabled = false;
    return;
  }
  els.logout.disabled = false;
  showAuth('');
  showToast('Signed out.');
}

function bindEvents() {
  els.modeSignin.addEventListener('click', () => setMode('signin'));
  els.modeSignup.addEventListener('click', () => setMode('signup'));
  els.switchMode.addEventListener('click', () => setMode(state.authMode === 'signin' ? 'signup' : 'signin'));
  els.togglePassword.addEventListener('click', () => {
    const revealing = els.password.type === 'password';
    els.password.type = revealing ? 'text' : 'password';
    els.togglePassword.textContent = revealing ? 'Hide' : 'Show';
    els.togglePassword.setAttribute('aria-pressed', String(revealing));
  });
  els.authForm.addEventListener('submit', (event) => void submitAuth(event));
  for (const field of [els.username, els.password]) {
    field.addEventListener('input', () => { setAuthError(''); });
  }
  els.logout.addEventListener('click', () => void logout());
  els.back.addEventListener('click', closeConversation);
  els.tabChat.addEventListener('click', () => switchTab('chat'));
  els.tabDetails.addEventListener('click', () => switchTab('details'));
  els.composer.addEventListener('submit', (event) => { event.preventDefault(); void sendMessage(); });
  els.messageInput.addEventListener('input', () => { updateComposer(); autoGrow(); });
  els.messageInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      void sendMessage();
    }
  });
  els.btnOpenJoin?.addEventListener('click', openJoinModal);
  els.btnCloseJoin?.addEventListener('click', closeJoinModal);
  els.btnCancelJoin?.addEventListener('click', closeJoinModal);
  els.joinForm?.addEventListener('submit', (event) => void submitJoinRoom(event));
  for (const button of [$('copy-invite-sidebar'), $('copy-invite-foot'), $('copy-invite-welcome')]) {
    button?.addEventListener('click', () => void copyInvite());
  }
  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button || button.disabled) return;
    const target = document.getElementById(button.dataset.copy);
    if (!target) return;
    try {
      const copied = await copyText(target.textContent.trim());
      if (!copied) throw new Error('copy failed');
      const original = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = original; }, 1400);
    } catch {
      showToast('Could not copy. Select the key and copy it manually.');
    }
  });
}

function init() {
  setMode('signin');
  setAuthBusy(false);
  bindEvents();
  updateComposer();
  void loadSession();
}

init();
