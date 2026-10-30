#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/identity.hpp"
#include "session/session.hpp"
#include "storage/local_store.hpp"

namespace jn {

struct SessionView {
  SessionId sid{};
  std::string label;
  PublicKey peer_pk{};
  bool group = false;
  bool active = false;
  bool initiator = false;
  std::vector<GroupMember> members;
};

class SessionManager {
 public:
  SessionManager(const Identity& identity, LocalStore& store);

  void load_stored_sessions();

  Session* add(Session session);
  Session* by_id(const SessionId& sid);
  const Session* by_id(const SessionId& sid) const;
  Session* active_with(const PublicKey& peer);
  std::vector<Session*> active_sessions();
  std::vector<SessionView> views() const;

  void persist(const Session& session);
  void add_member(Session& session, const GroupMember& member);
  void update_label(Session& session, const std::string& label);

  void note_message(Session& session);
  bool rotate_if_due(Session& session, RatchetUpdate& update);
  bool handle_ratchet(Session& session, const Bytes& control, std::string& error);
  void tick();

  std::optional<SessionView> view_for(const SessionId& sid) const;

 private:
  StoredSession to_stored(const Session& session) const;
  const Identity& identity_;
  LocalStore& store_;
  std::unordered_map<std::string, Session> sessions_;
  std::vector<StoredSession> stored_;
};

}  // namespace jn
