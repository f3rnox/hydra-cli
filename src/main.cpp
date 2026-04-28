#include "./cli_args.hpp"
#include "./config.hpp"
#include "./logging.hpp"
#include "./network.hpp"
#include "./progress.hpp"
#include "./session.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>
#include <vector>

namespace {

std::string build_session_key(const std::string &host_or_range,
                              const CliOptions &cli_options) {
  std::ostringstream key_stream;
  key_stream << host_or_range << '|' << "port=" << cli_options.target_port
             << '|' << "timeout=" << cli_options.timeout_seconds << '|'
             << "threads=" << cli_options.threads << '|'
             << "auth_threads=" << cli_options.auth_threads << '|'
             << "auth_timeout=" << cli_options.auth_timeout_seconds << '|'
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

bool send_telnet_line(int sockfd, const std::string &line) {
  const std::string payload = line + "\r\n";
  return send(sockfd, payload.data(), payload.size(), 0) ==
         static_cast<ssize_t>(payload.size());
}

void set_socket_timeout(int sockfd, int timeout_seconds) {
  timeval timeout{};
  timeout.tv_sec = timeout_seconds;
  timeout.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
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

std::string to_lower_ascii(std::string value) {
  for (char &c : value) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return value;
}

std::string escape_for_log(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (const char c : value) {
    switch (c) {
    case '\r':
      escaped += "\\r";
      break;
    case '\n':
      escaped += "\\n";
      break;
    case '\t':
      escaped += "\\t";
      break;
    default:
      escaped.push_back(c);
      break;
    }
  }
  return escaped;
}

bool contains_shell_prompt(const std::string &lower_response) {
  std::string normalized;
  normalized.reserve(lower_response.size());
  for (const char c : lower_response) {
    if (c != '\r') {
      normalized.push_back(c);
    }
  }

  std::stringstream lines(normalized);
  std::string line;
  while (std::getline(lines, line, '\n')) {
    while (!line.empty() &&
           std::isspace(static_cast<unsigned char>(line.back())) != 0) {
      line.pop_back();
    }
    if (!line.empty()) {
      const char last_char = line.back();
      if (last_char == '$' || last_char == '#' || last_char == '>') {
        return true;
      }
    }
  }

  return false;
}

bool socket_appears_open(int sockfd) {
  char probe_byte = '\0';
  const ssize_t peek_result =
      recv(sockfd, &probe_byte, 1, MSG_PEEK | MSG_DONTWAIT);
  if (peek_result == 0) {
    return false;
  }
  if (peek_result > 0) {
    return true;
  }
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

bool response_indicates_failed_auth(const std::string &response) {
  const std::string lower_response = to_lower_ascii(response);

  return lower_response.find("incorrect") != std::string::npos ||
         lower_response.find("failed") != std::string::npos ||
         lower_response.find("denied") != std::string::npos ||
         lower_response.find("invalid") != std::string::npos ||
         lower_response.find("bad password") != std::string::npos ||
         lower_response.find("authentication failure") != std::string::npos ||
         lower_response.find("login incorrect") != std::string::npos;
}

bool response_indicates_successful_auth(const std::string &response) {
  const std::string lower_response = to_lower_ascii(response);

  if (lower_response.empty()) {
    return false;
  }

  return lower_response.find("welcome") != std::string::npos ||
         lower_response.find("last login") != std::string::npos ||
         contains_shell_prompt(lower_response);
}

bool try_telnet_auth(int sockfd, const std::string &target_host,
                     int target_port, std::string &attempt_username,
                     const std::string &attempt_password,
                     std::ofstream *results_file, int auth_timeout_seconds) {
  set_socket_timeout(sockfd, auth_timeout_seconds);
  const std::string trying_message = "[auth] target=" + target_host + ":" +
                                     std::to_string(target_port) +
                                     " trying username='" + attempt_username +
                                     "' password='" + attempt_password + "'";
  log_stdout_line(trying_message);
  if (results_file != nullptr) {
    (*results_file) << "[auth] target=" << target_host << ":" << target_port
                    << " trying username='" << attempt_username
                    << "' password='" << attempt_password << "'\n";
  }
  const std::string initial_prompt = read_telnet_data(sockfd);
  if (!send_telnet_line(sockfd, attempt_username)) {
    return false;
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  const std::string password_prompt = read_telnet_data(sockfd);
  if (!send_telnet_line(sockfd, attempt_password)) {
    return false;
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  std::string auth_response = read_telnet_data(sockfd);
  bool failed_auth = response_indicates_failed_auth(auth_response);
  bool successful_auth = response_indicates_successful_auth(auth_response);
  bool open_socket_after_auth = socket_appears_open(sockfd);
  if (!failed_auth && !successful_auth) {
    const std::string auth_probe_marker = "__HYDRA_AUTH_OK__";
    if (send_telnet_line(sockfd, "echo " + auth_probe_marker)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(300));
      const std::string probe_response = read_telnet_data(sockfd);
      auth_response += probe_response;
      failed_auth = response_indicates_failed_auth(auth_response);
      successful_auth =
          failed_auth
              ? false
              : (response_indicates_successful_auth(auth_response) ||
                 auth_response.find(auth_probe_marker) != std::string::npos);
      open_socket_after_auth = socket_appears_open(sockfd);
    }
  }
  if (!failed_auth && !successful_auth && open_socket_after_auth) {
    successful_auth = true;
  }
  if (failed_auth || !successful_auth) {
    std::string escaped_response =
        "initial='" + escape_for_log(initial_prompt) + "' " +
        "password_prompt='" + escape_for_log(password_prompt) + "' " +
        "auth='" + escape_for_log(auth_response) + "'";
    constexpr size_t k_max_logged_response_size = 240;
    if (escaped_response.size() > k_max_logged_response_size) {
      escaped_response.resize(k_max_logged_response_size);
      escaped_response += "...";
    }
    log_stdout_line(
        "[auth] target=" + target_host + ":" + std::to_string(target_port) +
        " result=failed reason=" +
        (failed_auth ? "negative_response" : "missing_success_marker") +
        " socket_open=" + (open_socket_after_auth ? "true" : "false") +
        " response=" + escaped_response);
    return false;
  }

  const std::string success_message = "[auth] target=" + target_host + ":" +
                                      std::to_string(target_port) +
                                      " success username='" + attempt_username +
                                      "' password='" + attempt_password + "'";
  log_stdout_line(success_message);
  if (results_file != nullptr) {
    (*results_file) << "[auth] target=" << target_host << ":" << target_port
                    << " success username='" << attempt_username
                    << "' password='" << attempt_password << "'\n";
  }
  return true;
}

struct ConnectedTarget {
  std::string host;
  int socket_fd = -1;
};

struct AuthTargetTask {
  size_t target_index = 0;
  std::string host;
};

using CredentialPair = std::pair<std::string, std::string>;
const std::array<CredentialPair, 12> k_default_telnet_credentials = {{
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

  log_info(
      "Target: " + host_or_range +
      ", expanded hosts: " + std::to_string(targets.size()) +
      ", port: " + std::to_string(cli_options.target_port) + ", timeout: " +
      std::to_string(cli_options.timeout_seconds) + "s, threads: " +
      std::to_string(cli_options.threads > 0
                         ? cli_options.threads
                         : static_cast<int>(targets.size())) +
      ", auth-threads: " +
      std::to_string(cli_options.auth_threads > 0
                         ? cli_options.auth_threads
                         : static_cast<int>(targets.size())) +
      ", auth-timeout: " + std::to_string(cli_options.auth_timeout_seconds) +
      "s" + ", with-auth: " + (cli_options.with_auth ? "enabled" : "disabled") +
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
    results_file << "auth_threads=" << cli_options.auth_threads << "\n";
    results_file << "auth_timeout_seconds=" << cli_options.auth_timeout_seconds
                 << "\n";
    results_file << "without_tor="
                 << (cli_options.without_tor ? "true" : "false") << "\n";
  }

  Session session;
  std::filesystem::path session_file_path;
  std::unordered_set<std::string> resumed_connected_hosts;
  if (cli_options.with_session) {
    if (!ensure_sessions_dir_exists()) {
      log_error(
          "Failed to initialize session directory '~/.hydra-cli/sessions'");
      return 1;
    }

    const std::string session_key =
        build_session_key(host_or_range, cli_options);
    session_file_path = get_session_file_path(session_key);
    if (!session.open(session_file_path, session_key, targets.size())) {
      log_error("Failed to initialize session state file '" +
                session_file_path.string() + "'");
      return 1;
    }

    const std::vector<std::string> previous_hosts = session.connected_hosts();
    resumed_connected_hosts.insert(previous_hosts.begin(),
                                   previous_hosts.end());

    const size_t pending = session.connect_pending_count();
    const size_t completed = targets.size() - pending;
    if (completed > 0) {
      log_info("Resuming session: " + std::to_string(completed) + " of " +
               std::to_string(targets.size()) + " host(s) already scanned, " +
               std::to_string(previous_hosts.size()) +
               " previous connection(s) recorded");
    }

    if (session.auth_succeeded()) {
      const std::string saved_host = session.auth_success_host();
      const std::string saved_user = session.auth_success_username();
      const std::string saved_pass = session.auth_success_password();
      log_info("Resuming completed session: telnet auth previously succeeded "
               "on " +
               saved_host + ":" + std::to_string(cli_options.target_port));
      if (results_file.is_open()) {
        results_file << "auth_status=success\n";
        results_file << "auth_host=" << saved_host << "\n";
        results_file << "auth_username=" << saved_user << "\n";
        results_file << "auth_password=" << saved_pass << "\n";
        results_file << "resumed_from_session=true\n";
      }
      session.clear();
      return 0;
    }
  }

  std::vector<ConnectedTarget> connected_targets;
  int last_error = 0;
  std::mutex connection_mutex;
  const bool should_attempt_auth =
      cli_options.with_auth && cli_options.target_port == 23;
  const std::vector<CredentialPair> auth_credentials =
      cli_options.auth_combinations.empty()
          ? std::vector<CredentialPair>(k_default_telnet_credentials.begin(),
                                        k_default_telnet_credentials.end())
          : cli_options.auth_combinations;
  const std::string credential_source =
      cli_options.auth_combinations.empty() ? "default" : "custom";
  std::mutex auth_queue_mutex;
  std::condition_variable auth_queue_cv;
  std::deque<AuthTargetTask> auth_target_queue;
  std::atomic<bool> connect_scan_completed(false);
  std::atomic<bool> auth_succeeded(false);
  std::mutex auth_result_mutex;
  std::string successful_host;
  std::string successful_username;
  std::string successful_password;
  std::mutex results_file_mutex;
  std::vector<std::thread> auth_workers;

  if (should_attempt_auth) {
    log_info("Attempting telnet authentication using " + credential_source +
             " credentials while scanning");
    if (cli_options.with_session) {
      if (!session.auth_init(targets.size(), auth_credentials.size())) {
        log_error("Failed to persist auth session state to '" +
                  session_file_path.string() + "'");
      }
    }
    const size_t requested_auth_threads = static_cast<size_t>(
        cli_options.auth_threads > 0 ? cli_options.auth_threads
                                     : targets.size());
    const size_t auth_worker_count =
        std::min(targets.size(), requested_auth_threads);
    auth_workers.reserve(auth_worker_count);
    for (size_t worker_index = 0; worker_index < auth_worker_count;
         ++worker_index) {
      auth_workers.emplace_back([&auth_queue_mutex, &auth_queue_cv,
                                 &auth_target_queue, &connect_scan_completed,
                                 &auth_succeeded, &auth_result_mutex,
                                 &successful_host, &successful_username,
                                 &successful_password, &results_file_mutex,
                                 &results_file, &auth_credentials, &session,
                                 cli_options]() {
        while (true) {
          AuthTargetTask target_task;
          {
            std::unique_lock<std::mutex> queue_lock(auth_queue_mutex);
            auth_queue_cv.wait(queue_lock, [&auth_target_queue,
                                            &connect_scan_completed,
                                            &auth_succeeded]() {
              return !auth_target_queue.empty() ||
                     connect_scan_completed.load() || auth_succeeded.load();
            });
            if (auth_succeeded.load()) {
              break;
            }
            if (auth_target_queue.empty()) {
              if (connect_scan_completed.load()) {
                break;
              }
              continue;
            }
            target_task = std::move(auth_target_queue.front());
            auth_target_queue.pop_front();
          }

          {
            std::lock_guard<std::mutex> results_lock(results_file_mutex);
            if (results_file.is_open()) {
              results_file << "[auth] scanning target=" << target_task.host
                           << ":" << cli_options.target_port << "\n";
            }
          }

          for (size_t credential_index = 0;
               credential_index < auth_credentials.size(); ++credential_index) {
            if (auth_succeeded.load()) {
              break;
            }
            if (cli_options.with_session &&
                session.auth_should_skip(target_task.target_index,
                                         credential_index)) {
              continue;
            }
            const auto &[username, password] =
                auth_credentials[credential_index];
            const int auth_socket = connect_to_host_port(
                target_task.host, cli_options.target_port,
                cli_options.auth_timeout_seconds, cli_options.without_tor);
            if (auth_socket == -1) {
              if (cli_options.with_session) {
                session.auth_record(target_task.target_index, credential_index);
              }
              continue;
            }

            std::string target_username = username;
            std::string target_password = password;
            const bool target_auth_success = try_telnet_auth(
                auth_socket, target_task.host, cli_options.target_port,
                target_username, target_password, nullptr,
                cli_options.auth_timeout_seconds);
            close(auth_socket);

            if (cli_options.with_session) {
              session.auth_record(target_task.target_index, credential_index);
            }

            if (!target_auth_success) {
              continue;
            }

            const bool already_succeeded = auth_succeeded.exchange(true);
            if (!already_succeeded) {
              std::lock_guard<std::mutex> lock(auth_result_mutex);
              successful_host = target_task.host;
              successful_username = target_username;
              successful_password = target_password;
              if (cli_options.with_session) {
                session.auth_record_success(target_task.host, target_username,
                                            target_password);
              }
            }
            {
              std::lock_guard<std::mutex> results_lock(results_file_mutex);
              if (results_file.is_open()) {
                results_file << "[auth] target=" << target_task.host << ":"
                             << cli_options.target_port
                             << " auth_success=true\n";
              }
            }
            auth_queue_cv.notify_all();
            break;
          }
        }
      });
    }
  }

  std::vector<std::thread> workers;
  const size_t requested_threads = static_cast<size_t>(
      cli_options.threads > 0 ? cli_options.threads : targets.size());
  const size_t worker_count = std::min(targets.size(), requested_threads);
  workers.reserve(worker_count);
  std::atomic<size_t> next_target_index(0);
  const size_t connect_initial_pending = cli_options.with_session
                                             ? session.connect_pending_count()
                                             : targets.size();
  ProgressIndicator progress;
  progress.start(connect_initial_pending, "checking hosts");

  for (size_t worker_index = 0; worker_index < worker_count; ++worker_index) {
    workers.emplace_back([&progress, &connection_mutex, &connected_targets,
                          &last_error, &targets, &next_target_index, &session,
                          &auth_queue_mutex, &auth_target_queue, &auth_queue_cv,
                          should_attempt_auth, cli_options]() {
      while (true) {
        const size_t target_index = next_target_index.fetch_add(1);
        if (target_index >= targets.size()) {
          break;
        }

        if (cli_options.with_session &&
            session.connect_should_skip(target_index)) {
          continue;
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
        const bool connected = candidate_socket != -1;

        {
          std::lock_guard<std::mutex> lock(connection_mutex);
          if (connected) {
            connected_targets.push_back({target_host, candidate_socket});
            if (should_attempt_auth) {
              std::lock_guard<std::mutex> queue_lock(auth_queue_mutex);
              auth_target_queue.push_back({target_index, target_host});
              auth_queue_cv.notify_one();
            }
          } else if (candidate_error != 0) {
            last_error = candidate_error;
          } else {
            last_error = ETIMEDOUT;
          }
        }

        if (cli_options.with_session) {
          session.connect_record(target_index, connected, target_host);
        }

        progress.increment();
      }
    });
  }

  for (std::thread &worker : workers) {
    worker.join();
  }
  connect_scan_completed.store(true);
  auth_queue_cv.notify_all();
  progress.stop("done");

  if (cli_options.with_session) {
    for (const std::string &previous_host : resumed_connected_hosts) {
      const bool already_present =
          std::any_of(connected_targets.begin(), connected_targets.end(),
                      [&previous_host](const ConnectedTarget &target) {
                        return target.host == previous_host;
                      });
      if (!already_present) {
        connected_targets.push_back({previous_host, -1});
      }
    }
    session.connect_finalize();
  }

  if (connected_targets.empty()) {
    if (cli_options.with_session) {
      session.clear();
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
  log_info("Connected to " + std::to_string(connected_targets.size()) +
           " target(s) on port " + std::to_string(cli_options.target_port) +
           (cli_options.without_tor ? " directly" : " through Tor"));
#endif
  if (results_file.is_open()) {
    results_file << "connection_status=success\n";
    results_file << "connected_targets=" << connected_targets.size() << "\n";
    for (const ConnectedTarget &target : connected_targets) {
      results_file << "connected_host=" << target.host << "\n";
    }
  }

  if (should_attempt_auth) {
    for (std::thread &auth_worker : auth_workers) {
      auth_worker.join();
    }

    if (!auth_succeeded.load()) {
      log_error("Telnet authentication attempt failed");
      if (results_file.is_open()) {
        results_file << "auth_status=failed\n";
      }
      for (ConnectedTarget &target : connected_targets) {
        if (target.socket_fd != -1) {
          close(target.socket_fd);
          target.socket_fd = -1;
        }
      }
      if (cli_options.with_session) {
        session.clear();
      }
      return 1;
    }
    log_info("Telnet authentication succeeded on " + successful_host + ":" +
             std::to_string(cli_options.target_port));
    if (results_file.is_open()) {
      results_file << "auth_status=success\n";
      results_file << "auth_host=" << successful_host << "\n";
      results_file << "auth_username=" << successful_username << "\n";
      results_file << "auth_password=" << successful_password << "\n";
    }
    if (cli_options.with_session) {
      session.clear();
    }
    return 0;
  }

  const std::string connected_host = connected_targets.front().host;
  const int sockfd = connected_targets.front().socket_fd;
  for (size_t index = 1; index < connected_targets.size(); ++index) {
    if (connected_targets[index].socket_fd != -1) {
      close(connected_targets[index].socket_fd);
      connected_targets[index].socket_fd = -1;
    }
  }

  log_stdout_chunk(connected_host + ":" +
                   std::to_string(cli_options.target_port) + " ");

  char buffer[1024];
  while (true) {
    const ssize_t bytes_read = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_read > 0) {
      log_stdout_chunk(std::string(buffer, static_cast<size_t>(bytes_read)));
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

  flush_stdout_buffer();
  if (results_file.is_open()) {
    results_file << "read_status=completed\n";
  }
  close(sockfd);
  if (cli_options.with_session) {
    session.clear();
  }
  log_info("Connection closed");
  return 0;
}
