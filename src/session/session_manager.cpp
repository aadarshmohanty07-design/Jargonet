#include "session/session_manager.hpp"

#include <algorithm>

#include "core/encoding.hpp"

namespace jn {
namespace {

std::string sid_key(const SessionId& sid) { return hex_encode(sid.data(), sid.size()); }

GroupMember member_from(const StoredContact& contact) {
  return GroupMember{contact.pk, contact.sign_pk, contact.username};
}

StoredContact contact_from(const GroupMember& member) {
  return StoredContact{member.pk, member.sign_pk, member.name};
}

}  // namespace

SessionManager::SessionManager(const Identity& identity, LocalStore& store)
    : identity_(identity), store_(store) {}

void SessionManager::load_stored_sessions() { stored_ = store_.sessions(); }

Session* SessionManager::add(Session session) {
  session.established = std::chrono::steady_clock::now();
  if (session.last_ratchet.time_since_epoch().count() == 0) {
    session.last_ratchet = session.established;
  }
  session.ratchet_leader = !session.group && session.initiator;

  StoredSession record = to_stored(session);
  store_.upsert_session(record);
  const std::string key = sid_key(session.sid);
  auto [it, inserted] = sessions_.insert_or_assign(key, std::move(session));
  (void)inserted;
  return &it->second;
}

Session* SessionManager::by_id(const SessionId& sid) {
  auto it = sessions_.find(sid_key(sid));
  return it == sessions_.end() ? nullptr : &it->second;
}

const Session* SessionManager::by_id(const SessionId& sid) const {
  auto it = sessions_.find(sid_key(sid));
  return it == sessions_.end() ? nullptr : &it->second;
}

Session* SessionManager::active_with(const PublicKey& peer) {
  for (auto& [key, session] : sessions_) {
    (void)key;
    if (!session.group && session.peer_pk == peer) return &session;
  }
  return nullptr;
}

std::vector<Session*> SessionManager::active_sessions() {
  std::vector<Session*> out;
  for (auto& [key, session] : sessions_) {
    (void)key;
    out.push_back(&session);
  }
  return out;
}

StoredSession SessionManager::to_stored(const Session& session) const {
  StoredSession record;
  record.sid = session.sid;
  record.peer_pk = session.peer_pk;
  record.peer_sign_pk = session.peer_sign_pk;
  record.label = session.label;
  record.group = session.group;
  record.initiator = session.initiator;
  for (const auto& member : session.members) record.members.push_back(contact_from(member));
  return record;
}

void SessionManager::persist(const Session& session) {
  store_.upsert_session(to_stored(session));
}

void SessionManager::add_member(Session& session, const GroupMember& member) {
  if (member.pk == kZeroPublicKey) return;
  for (auto& existing : session.members) {
    if (existing.pk == member.pk) {
      existing.sign_pk = member.sign_pk;
      if (!member.name.empty()) existing.name = member.name;
      persist(session);
      return;
    }
  }
  session.members.push_back(member);
  persist(session);
}

void SessionManager::update_label(Session& session, const std::string& label) {
  session.label = label;
  persist(session);
}

std::vector<SessionView> SessionManager::views() const {
  std::vector<SessionView> out;
  std::vector<std::string> seen;

  auto push = [&](const Session& session, bool active) {
    SessionView view;
    view.sid = session.sid;
    view.label = session.label;
    view.peer_pk = session.peer_pk;
    view.group = session.group;
    view.initiator = session.initiator;
    view.active = active;
    view.members = session.members;
    out.push_back(std::move(view));
  };

  for (const auto& [key, session] : sessions_) {
    (void)key;
    seen.push_back(sid_key(session.sid));
    push(session, true);
  }
  for (const auto& stored : stored_) {
    const std::string key = sid_key(stored.sid);
    if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
    SessionView view;
    view.sid = stored.sid;
    view.label = stored.label;
    view.peer_pk = stored.peer_pk;
    view.group = stored.group;
    view.initiator = stored.initiator;
    view.active = false;
    for (const auto& member : stored.members) view.members.push_back(member_from(member));
    out.push_back(std::move(view));
  }
  std::sort(out.begin(), out.end(), [](const SessionView& a, const SessionView& b) {
    return a.label < b.label;
  });
  return out;
}

std::optional<SessionView> SessionManager::view_for(const SessionId& sid) const {
  if (const Session* session = by_id(sid)) {
    SessionView view;
    view.sid = session->sid;
    view.label = session->label;
    view.peer_pk = session->peer_pk;
    view.group = session->group;
    view.active = true;
    view.initiator = session->initiator;
    view.members = session->members;
    return view;
  }
  for (const auto& stored : stored_) {
    if (stored.sid == sid) {
      SessionView view;
      view.sid = stored.sid;
      view.label = stored.label;
      view.peer_pk = stored.peer_pk;
      view.group = stored.group;
      view.active = false;
      view.initiator = stored.initiator;
      for (const auto& member : stored.members) view.members.push_back(member_from(member));
      return view;
    }
  }
  return std::nullopt;
}

void SessionManager::note_message(Session& session) { ++session.messages_since_ratchet; }

bool SessionManager::rotate_if_due(Session& session, RatchetUpdate& update) {
  if (!session.should_rotate(std::chrono::steady_clock::now())) return false;
  auto prepared = prepare_ratchet(session, identity_.pk, session.peer_pk);
  if (!prepared) return false;
  update = std::move(*prepared);
  return true;
}

bool SessionManager::handle_ratchet(Session& session, const Bytes& control, std::string& error) {
  if (session.group) {
    error = "groups do not ratchet";
    return false;
  }
  return apply_ratchet(session, identity_.pk, identity_.sk, session.peer_pk, control, error);
}

void SessionManager::tick() {
  const auto now = std::chrono::steady_clock::now();
  for (auto& [key, session] : sessions_) {
    (void)key;
    expire_previous_keys(session, now);
  }
}

}  // namespace jn
