#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>

#include "net/rendezvous_server.hpp"

namespace {
std::atomic<bool> g_stop{false};

void handle_signal(int) { g_stop = true; }
}  // namespace

int main(int argc, char** argv) {
  std::uint16_t port = 47400;
  std::uint32_t ttl = 120;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = static_cast<std::uint16_t>(std::stoul(argv[++i]));
    } else if (arg == "--ttl" && i + 1 < argc) {
      ttl = static_cast<std::uint32_t>(std::stoul(argv[++i]));
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: jargonet-rendezvous [--port 47400] [--ttl 120]\n"
                   "Matches opaque rendezvous tags to observed UDP endpoints.\n"
                   "It never sees usernames, public keys, session ids or message content,\n"
                   "and it does not log IP addresses.\n";
      return 0;
    } else {
      std::cerr << "unknown option: " << arg << "\n";
      return 1;
    }
  }

  jn::RendezvousServer::Config config;
  config.bind = jn::Endpoint{"0.0.0.0", port};
  config.default_ttl_seconds = ttl;

  jn::RendezvousServer server(config);
  std::string error;
  if (!server.start(error)) {
    std::cerr << "cannot start rendezvous: " << error << "\n";
    return 1;
  }

  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);

  std::cout << "Jargonet rendezvous listening on UDP " << server.port()
            << " (tag ttl " << ttl << "s). Logs contain no IP addresses.\n"
            << std::flush;

  while (!g_stop) {
    server.run_once(200);
  }
  server.stop();
  std::cout << "rendezvous stopped\n";
  return 0;
}
