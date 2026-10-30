#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "app/node.hpp"
#include "core/crypto.hpp"
#include "core/encoding.hpp"
#include "core/file_util.hpp"
#include "core/identity.hpp"
#include "ui/console.hpp"

namespace {

using namespace jn;

void print_usage() {
  std::cout <<
      "Jargonet " JARGONET_VERSION " - private peer-to-peer chat\n\n"
      "Usage:\n"
      "  jargonet init --name <username> [--data-dir DIR] [--password-stdin]\n"
      "  jargonet start [options]\n\n"
      "Start options:\n"
      "  --data-dir DIR          identity and encrypted history directory\n"
      "  --port PORT             UDP listen port (default: ephemeral)\n"
      "  --rendezvous HOST:PORT  zero-knowledge rendezvous service\n"
      "  --stun HOST:PORT        STUN server for invite endpoint hints\n"
      "  --advertise HOST:PORT   manual reachable endpoint for invites\n"
      "  --no-relay              do not relay onions for other peers\n"
      "  --auto-accept           accept chat requests automatically\n"
      "  --mode MODE             auto | direct | onion (default auto)\n"
      "  --password-stdin        read the password from stdin (automation)\n";
}

bool stdin_is_tty() {
#ifdef _WIN32
  return _isatty(_fileno(stdin)) != 0;
#else
  return ::isatty(STDIN_FILENO) != 0;
#endif
}

std::string read_password_tty(const std::string& prompt) {
  std::cout << prompt << std::flush;
  std::string password;
#ifdef _WIN32
  int ch = 0;
  while ((ch = _getch()) != '\r' && ch != '\n') {
    if (ch == 3) {
      std::cout << "\n";
      std::exit(130);
    }
    if (ch == 8) {
      if (!password.empty()) {
        password.pop_back();
        std::cout << "\b \b" << std::flush;
      }
      continue;
    }
    if (ch >= 32 && ch < 127) {
      password.push_back(static_cast<char>(ch));
      std::cout << '*' << std::flush;
    }
  }
  std::cout << "\n";
#else
  termios old{};
  if (tcgetattr(STDIN_FILENO, &old) != 0) {
    std::getline(std::cin, password);
    return password;
  }
  termios quiet = old;
  quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
  std::getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSANOW, &old);
  std::cout << "\n";
#endif
  return password;
}

std::string read_password_line() {
  std::string line;
  std::getline(std::cin, line);
  return line;
}

std::string read_password(const std::string& prompt, bool confirm, bool from_stdin) {
  if (from_stdin || !stdin_is_tty()) {
    std::string password = read_password_line();
    if (password.empty()) {
      std::cerr << "password is required\n";
      std::exit(1);
    }
    return password;
  }
  for (int attempt = 0; attempt < 3; ++attempt) {
    std::string first = read_password_tty(prompt);
    if (!confirm) return first;
    std::string second = read_password_tty("Confirm password: ");
    if (first == second) return first;
    std::cout << "Passwords do not match. Try again.\n";
  }
  std::cerr << "Too many mismatches.\n";
  std::exit(1);
}

bool parse_port(const std::string& text, std::uint16_t& port) {
  try {
    const unsigned long value = std::stoul(text);
    if (value > 65535) return false;
    port = static_cast<std::uint16_t>(value);
    return true;
  } catch (...) {
    return false;
  }
}

std::optional<Endpoint> parse_endpoint_arg(const std::string& value, const char* flag) {
  auto endpoint = Endpoint::parse(value);
  if (!endpoint) {
    std::cerr << "invalid " << flag << " value: " << value << "\n";
  }
  return endpoint;
}

std::string prompt_username() {
  std::cout << "Username: " << std::flush;
  std::string username;
  std::getline(std::cin, username);
  return trim(username);
}

int run_init(const std::vector<std::string>& args) {
  std::string username;
  std::filesystem::path data_dir = default_data_dir();
  bool password_stdin = false;

  for (std::size_t i = 0; i < args.size(); ++i) {
    if (args[i] == "--name" && i + 1 < args.size()) {
      username = args[++i];
    } else if (args[i] == "--data-dir" && i + 1 < args.size()) {
      data_dir = args[++i];
    } else if (args[i] == "--password-stdin") {
      password_stdin = true;
    } else {
      std::cerr << "unknown init option: " << args[i] << "\n";
      return 1;
    }
  }

  if (username.empty()) username = prompt_username();
  if (username.empty()) {
    std::cerr << "a username is required (--name)\n";
    return 1;
  }

  try {
    IdentityManager::validate_username(username);
  } catch (const IdentityError& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }

  if (IdentityManager::exists(data_dir)) {
    std::cerr << "an identity already exists in " << data_dir.string()
              << "\nUse that identity with: jargonet start --data-dir \"" << data_dir.string()
              << "\"\nPanic wipe it first if you want a new identity.\n";
    return 1;
  }

  std::string password = read_password("Choose a password: ", !password_stdin, password_stdin);
  try {
    IdentityManager::validate_password(password);
        auto identity = IdentityManager::create(data_dir, username, password);
    std::cout << "\nIdentity created for " << identity.username << "\n"
              << "Fingerprint: " << identity.fingerprint() << "\n"
              << "Data directory: " << data_dir.string() << "\n\n"
              << "There is no recovery and no reset. If you lose the password or the key,\n"
              << "this identity is gone. Back up the data directory if you accept that risk.\n\n"
              << "Next: jargonet start --data-dir \"" << data_dir.string()
              << "\" and run /invite there.\n";
    CryptoEngine::wipe(password.data(), password.size());
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "identity creation failed: " << e.what() << "\n";
    return 1;
  }
}

int run_start(const std::vector<std::string>& args) {
  NodeConfig config;
  config.data_dir = default_data_dir();
  bool password_stdin = false;

  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& arg = args[i];
    auto need_value = [&](const char* flag) -> std::optional<std::string> {
      if (i + 1 >= args.size()) {
        std::cerr << "missing value for " << flag << "\n";
        return std::nullopt;
      }
      return args[++i];
    };

    if (arg == "--data-dir") {
      auto value = need_value("--data-dir");
      if (!value) return 1;
      config.data_dir = *value;
    } else if (arg == "--port") {
      auto value = need_value("--port");
      if (!value) return 1;
      if (!parse_port(*value, config.listen_port)) {
        std::cerr << "invalid port: " << *value << "\n";
        return 1;
      }
    } else if (arg == "--rendezvous") {
      auto value = need_value("--rendezvous");
      if (!value) return 1;
      auto ep = parse_endpoint_arg(*value, "--rendezvous");
      if (!ep) return 1;
      config.rendezvous = *ep;
    } else if (arg == "--stun") {
      auto value = need_value("--stun");
      if (!value) return 1;
      auto ep = parse_endpoint_arg(*value, "--stun");
      if (!ep) return 1;
      config.stun = *ep;
    } else if (arg == "--advertise") {
      auto value = need_value("--advertise");
      if (!value) return 1;
      auto ep = parse_endpoint_arg(*value, "--advertise");
      if (!ep) return 1;
      config.advertise = *ep;
    } else if (arg == "--no-relay") {
      config.relay_enabled = false;
    } else if (arg == "--relay") {
      config.relay_enabled = true;
    } else if (arg == "--auto-accept") {
      config.auto_accept = true;
    } else if (arg == "--mode") {
      auto value = need_value("--mode");
      if (!value) return 1;
      if (*value != "auto" && *value != "direct" && *value != "onion") {
        std::cerr << "mode must be auto, direct or onion\n";
        return 1;
      }
      config.mode = *value;
    } else if (arg == "--password-stdin") {
      password_stdin = true;
    } else {
      std::cerr << "unknown start option: " << arg << "\n";
      return 1;
    }
  }

  if (!IdentityManager::exists(config.data_dir)) {
    std::cerr << "no identity in " << config.data_dir.string()
              << "\nRun: jargonet init --name <username> --data-dir \"" << config.data_dir.string()
              << "\"\n";
    return 1;
  }

  std::string password = read_password("Password: ", false, password_stdin);
  try {
    Identity identity = IdentityManager::unlock(config.data_dir, password);
    ConsoleApp app(std::move(config), std::move(identity), password);
    CryptoEngine::wipe(password.data(), password.size());
    password.clear();
    return app.run();
  } catch (const std::exception& e) {
    std::cerr << "cannot open identity: " << e.what() << "\n";
    return 1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> args(argv + 1, argv + argc);
  if (args.empty()) {
    print_usage();
    return 1;
  }
  CryptoEngine::init();

  const std::string command = args[0];
  args.erase(args.begin());
  try {
    if (command == "init") return run_init(args);
    if (command == "start") return run_start(args);
    if (command == "version" || command == "--version" || command == "-v") {
      std::cout << "Jargonet " JARGONET_VERSION "\n";
      return 0;
    }
    if (command == "help" || command == "--help" || command == "-h") {
      print_usage();
      return 0;
    }
    std::cerr << "unknown command: " << command << "\n";
    print_usage();
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return 1;
  }
}
