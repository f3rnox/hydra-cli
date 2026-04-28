#include "./cli_args.hpp"
#include "./config.hpp"
#include "./logging.hpp"
#include "./network.hpp"
#include "./progress.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

std::string build_session_key(const std::string &host_or_range,
                              const CliOptions &cli_options) {
  std::ostringstream key_stream;
  key_stream << host_or_range << '|' << "port=" << cli_options.target_port
             << '|' << "timeout=" << cli_options.timeout_seconds << '|'
             << "threads=" << cli_options.threads << '|'
             << "auth=" << (cli_options.with_auth ? 1 : 0) << '|'
             << "without_tor=" << (cli_options.without_tor ? 1 : 0);
  return key_stream.str();
}

std::filesystem::path get_sessions_dir_path() {
  const char *home_env = std::getenv("HOME");
  const std::filesystem::path home_path = home_env != nullptr
                                              ? std::filesystem::path(home_env)
                                              : std::filesystem::current_path();
  return home_path / ".hydra-cli" / "sessions";
}

std::filesystem::path get_session_file_path(const std::string &session_key) {
  const size_t session_hash = std::hash<std::string>{}(session_key);
  std::ostringstream file_name;
  file_name << "session-" << std::hex << session_hash << ".state";
  return get_sessions_dir_path() / file_name.str();
}

bool ensure_sessions_dir_exists() {
  std::error_code ec;
  const std::filesystem::path sessions_dir = get_sessions_dir_path();
  if (std::filesystem::exists(sessions_dir, ec)) {
    return !ec;
  }
  std::filesystem::create_directories(sessions_dir, ec);
  return !ec;
}

size_t load_resume_index(const std::filesystem::path &session_file_path) {
  std::ifstream session_file(session_file_path);
  if (!session_file.is_open()) {
    return 0;
  }

  size_t resume_index = 0;
  session_file >> resume_index;
  if (!session_file.good() && !session_file.eof()) {
    return 0;
  }
  return resume_index;
}

bool save_resume_index(const std::filesystem::path &session_file_path,
                       size_t resume_index) {
  const std::filesystem::path temp_path = session_file_path.string() + ".tmp";
  {
    std::ofstream temp_file(temp_path, std::ios::trunc);
    if (!temp_file.is_open()) {
      return false;
    }
    temp_file << resume_index << "\n";
    if (!temp_file.good()) {
      return false;
    }
  }

  std::error_code ec;
  std::filesystem::rename(temp_path, session_file_path, ec);
  if (ec) {
    std::filesystem::remove(session_file_path, ec);
    ec.clear();
    std::filesystem::rename(temp_path, session_file_path, ec);
  }
  return !ec;
}

void clear_resume_file(const std::filesystem::path &session_file_path) {
  std::error_code ec;
  std::filesystem::remove(session_file_path, ec);
}

bool send_telnet_line(int sockfd, const std::string &line) {
  const std::string payload = line + "\r\n";
  return send(sockfd, payload.data(), payload.size(), 0) ==
         static_cast<ssize_t>(payload.size());
}

std::string read_telnet_data(int sockfd) {
  char buffer[1024];
  std::string collected;
  while (true) {
    const ssize_t bytes_read = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_read > 0) {
      collected.append(buffer, static_cast<size_t>(bytes_read));
      continue;
    }
    break;
  }
  return collected;
}

bool response_indicates_failed_auth(const std::string &response) {
  const std::string lower_response = [&response]() {
    std::string lowered = response;
    for (char &c : lowered) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return lowered;
  }();

  return lower_response.find("incorrect") != std::string::npos ||
         lower_response.find("failed") != std::string::npos ||
         lower_response.find("denied") != std::string::npos ||
         lower_response.find("invalid") != std::string::npos ||
         lower_response.find("bad password") != std::string::npos ||
         lower_response.find("login:") != std::string::npos ||
         lower_response.find("password:") != std::string::npos;
}

bool try_telnet_auth(int sockfd, const std::string &target_host,
                     int target_port, std::string &successful_username,
                     std::string &successful_password,
                     std::ofstream *results_file) {
  const std::array<std::pair<std::string, std::string>, 12> credentials = {{
      {"admin", "admin"},
      {"admin", "password"},
      {"root", "root"},
      {"root", ""},
      {"ubnt", "ubnt"},
      {"pi", "raspberry"},
      {"admin", "1234"},
      {"admin", "12345"},
      {"root", "toor"},
      {"user", "user"},
      {"admin", "admin1"},
      {"cisco", "cisco"},
  }};

  for (const auto &[username, password] : credentials) {
    std::cout << "[auth] target=" << target_host << ":" << target_port
              << " trying username='" << username << "' password='" << password
              << "'\n";
    if (results_file != nullptr) {
      (*results_file) << "[auth] target=" << target_host << ":" << target_port
                      << " trying username='" << username << "' password='"
                      << password << "'\n";
    }
    read_telnet_data(sockfd);
    if (!send_telnet_line(sockfd, username)) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    read_telnet_data(sockfd);
    if (!send_telnet_line(sockfd, password)) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const std::string auth_response = read_telnet_data(sockfd);
    if (!response_indicates_failed_auth(auth_response)) {
      successful_username = username;
      successful_password = password;
      std::cout << "[auth] target=" << target_host << ":" << target_port
                << " success username='" << successful_username
                << "' password='" << successful_password << "'\n";
      if (results_file != nullptr) {
        (*results_file) << "[auth] target=" << target_host << ":" << target_port
                        << " success username='" << successful_username
                        << "' password='" << successful_password << "'\n";
      }
      return true;
    }
  }

  return false;
}

} // namespace

int main(int argc, char **argv) {
  log_info("hydra-cli started");
  if (argc == 2 && std::string(argv[1]) == "--help") {
    print_usage(argv[0]);
    return 0;
  }

  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string host_or_range = argv[1];
  CliOptions cli_options;
  if (!parse_cli_options(argc, argv, cli_options)) {
    print_usage(argv[0]);
    return 1;
  }

  std::vector<std::string> targets;
  if (!parse_host_range(host_or_range, targets)) {
    targets.push_back(host_or_range);
  }

  log_info("Target: " + host_or_range +
           ", expanded hosts: " + std::to_string(targets.size()) +
           ", port: " + std::to_string(cli_options.target_port) +
           ", timeout: " + std::to_string(cli_options.timeout_seconds) +
           "s, threads: " +
           std::to_string(cli_options.threads > 0
                              ? cli_options.threads
                              : static_cast<int>(targets.size())) +
           ", with-auth: " + (cli_options.with_auth ? "enabled" : "disabled") +
           ", session: " + (cli_options.with_session ? "enabled" : "disabled") +
           ", tor: " + (cli_options.without_tor ? "disabled" : "enabled"));

  std::ofstream results_file;
  if (!cli_options.save_results_path.empty()) {
    results_file.open(cli_options.save_results_path,
                      std::ios::out | std::ios::trunc);
    if (!results_file.is_open()) {
      log_error("Failed to open results file '" +
                cli_options.save_results_path + "'");
      return 1;
    }
    results_file << "target=" << host_or_range << "\n";
    results_file << "port=" << cli_options.target_port << "\n";
    results_file << "timeout_seconds=" << cli_options.timeout_seconds << "\n";
    results_file << "with_auth=" << (cli_options.with_auth ? "true" : "false")
                 << "\n";
    results_file << "without_tor="
                 << (cli_options.without_tor ? "true" : "false") << "\n";
  }

  std::filesystem::path session_file_path;
  size_t resume_index = 0;
  if (cli_options.with_session) {
    if (!ensure_sessions_dir_exists()) {
      log_error(
          "Failed to initialize session directory '~/.hydra-cli/sessions'");
      return 1;
    }

    const std::string session_key =
        build_session_key(host_or_range, cli_options);
    session_file_path = get_session_file_path(session_key);
    resume_index = load_resume_index(session_file_path);
    if (resume_index >= targets.size()) {
      resume_index = 0;
      clear_resume_file(session_file_path);
    }
    if (resume_index > 0) {
      log_info("Resuming session from host index " +
               std::to_string(resume_index) + " of " +
               std::to_string(targets.size()));
    }
  }

  int sockfd = -1;
  std::string connected_host;
  int last_error = 0;
  std::mutex connection_mutex;
  std::mutex session_mutex;
  std::vector<std::thread> workers;
  const size_t requested_threads = static_cast<size_t>(
      cli_options.threads > 0 ? cli_options.threads : targets.size());
  const size_t worker_count = std::min(targets.size(), requested_threads);
  workers.reserve(worker_count);
  std::atomic<size_t> next_target_index(resume_index);
  ProgressIndicator progress;
  progress.start(targets.size() - resume_index, "checking hosts");

  for (size_t worker_index = 0; worker_index < worker_count; ++worker_index) {
    workers.emplace_back([&progress, &connection_mutex, &connected_host,
                          &last_error, &sockfd, &targets, &next_target_index,
                          &session_mutex, &session_file_path, cli_options]() {
      while (true) {
        const size_t target_index = next_target_index.fetch_add(1);
        if (target_index >= targets.size()) {
          break;
        }

        const std::string &target_host = targets[target_index];
#ifdef DEBUG
        log_info("Trying " + target_host + ":" +
                 std::to_string(cli_options.target_port));
#endif
        const int candidate_socket = connect_to_host_port(
            target_host, cli_options.target_port, cli_options.timeout_seconds,
            cli_options.without_tor);
        const int candidate_error = errno;

        std::lock_guard<std::mutex> lock(connection_mutex);
        if (candidate_socket != -1) {
          if (sockfd == -1) {
            sockfd = candidate_socket;
            connected_host = target_host;
          } else {
            close(candidate_socket);
          }
        } else if (candidate_error != 0) {
          last_error = candidate_error;
        } else {
          last_error = ETIMEDOUT;
        }

        progress.increment();
        if (cli_options.with_session) {
          const size_t next_index_snapshot = next_target_index.load();
          if (next_index_snapshot % 10 == 0 ||
              next_index_snapshot == targets.size()) {
            std::lock_guard<std::mutex> session_lock(session_mutex);
            save_resume_index(session_file_path, next_index_snapshot);
          }
        }
      }
    });
  }

  for (std::thread &worker : workers) {
    worker.join();
  }
  progress.stop("done");
  if (cli_options.with_session) {
    std::lock_guard<std::mutex> session_lock(session_mutex);
    save_resume_index(session_file_path, next_target_index.load());
  }

  if (sockfd == -1) {
    if (cli_options.with_session) {
      clear_resume_file(session_file_path);
    }
    errno = last_error;
    const std::string connection_mode = cli_options.without_tor
                                            ? "direct connection"
                                            : "Tor SOCKS5 proxy 127.0.0.1:9050";
    log_error("Failed to connect to all targets in '" + host_or_range +
              "' using " + connection_mode + " (" + std::strerror(errno) + ")");
    if (results_file.is_open()) {
      results_file << "connection_status=failed\n";
      results_file << "error=" << std::strerror(errno) << "\n";
    }
    return 1;
  }

#ifdef DEBUG
  log_info("Connected to " + connected_host + ":" +
           std::to_string(cli_options.target_port) +
           (cli_options.without_tor ? " directly" : " through Tor"));
#endif
  if (results_file.is_open()) {
    results_file << "connection_status=success\n";
    results_file << "connected_host=" << connected_host << "\n";
  }

  if (cli_options.with_auth && cli_options.target_port == 23) {
    log_info("Attempting telnet authentication using default credentials");
    std::string successful_username;
    std::string successful_password;
    if (!try_telnet_auth(sockfd, connected_host, cli_options.target_port,
                         successful_username, successful_password,
                         results_file.is_open() ? &results_file : nullptr)) {
      log_error("Telnet authentication attempt failed");
      if (results_file.is_open()) {
        results_file << "auth_status=failed\n";
      }
      close(sockfd);
      if (cli_options.with_session) {
        clear_resume_file(session_file_path);
      }
      return 1;
    }
    if (results_file.is_open()) {
      results_file << "auth_status=success\n";
      results_file << "auth_username=" << successful_username << "\n";
      results_file << "auth_password=" << successful_password << "\n";
    }
    close(sockfd);
    if (cli_options.with_session) {
      clear_resume_file(session_file_path);
    }
    return 0;
  }

  std::cout << connected_host << ":" << cli_options.target_port << " ";

  char buffer[1024];
  while (true) {
    const ssize_t bytes_read = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_read > 0) {
      std::cout.write(buffer, bytes_read);
      std::cout.flush();
      continue;
    }

    if (bytes_read == 0) {
      break;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
#ifdef DEBUG
      log_info("No more data before read timeout");
#endif
      break;
    }

    log_error(std::string("Read error: ") + std::strerror(errno));
    close(sockfd);
    return 1;
  }

  std::cout << "\n";
  if (results_file.is_open()) {
    results_file << "read_status=completed\n";
  }
  close(sockfd);
  if (cli_options.with_session) {
    clear_resume_file(session_file_path);
  }
  log_info("Connection closed");
  return 0;
}
