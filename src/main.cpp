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

bool set_socket_timeout(int sockfd, int timeout_seconds) {
  timeval timeout{};
  timeout.tv_sec = timeout_seconds;
  timeout.tv_usec = 0;
  const int recv_timeout_result =
      setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  const int send_timeout_result =
      setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  return recv_timeout_result == 0 && send_timeout_result == 0;
}

std::string read_telnet_data(int sockfd) {
  std::string buffer(1024, '\0');
  std::string collected;
  while (true) {
    if (const ssize_t bytes_read =
            recv(sockfd, buffer.data(), buffer.size(), 0);
        bytes_read > 0) {
      collected.append(buffer.data(), static_cast<size_t>(bytes_read));
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
                     int target_port, const std::string &attempt_username,
                     const std::string &attempt_password,
                     std::ofstream *results_file, int auth_timeout_seconds) {
  if (!set_socket_timeout(sockfd, auth_timeout_seconds)) {
    return false;
  }
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
    if (constexpr size_t k_max_logged_response_size = 240;
        escaped_response.size() > k_max_logged_response_size) {
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

struct AuthWorkerContext {
  std::mutex *auth_queue_mutex = nullptr;
  std::condition_variable *auth_queue_cv = nullptr;
  std::deque<AuthTargetTask> *auth_target_queue = nullptr;
  std::atomic<bool> *connect_scan_completed = nullptr;
  std::atomic<bool> *auth_succeeded = nullptr;
  std::mutex *auth_result_mutex = nullptr;
  std::string *successful_host = nullptr;
  std::string *successful_username = nullptr;
  std::string *successful_password = nullptr;
  std::mutex *results_file_mutex = nullptr;
  std::ofstream *results_file = nullptr;
  const std::vector<CredentialPair> *auth_credentials = nullptr;
  Session *session = nullptr;
  const CliOptions *cli_options = nullptr;
};

struct ConnectWorkerContext {
  ProgressIndicator *progress = nullptr;
  std::mutex *connection_mutex = nullptr;
  std::vector<ConnectedTarget> *connected_targets = nullptr;
  int *last_error = nullptr;
  const std::vector<std::string> *targets = nullptr;
  std::atomic<size_t> *next_target_index = nullptr;
  Session *session = nullptr;
  std::mutex *auth_queue_mutex = nullptr;
  std::deque<AuthTargetTask> *auth_target_queue = nullptr;
  std::condition_variable *auth_queue_cv = nullptr;
  bool should_attempt_auth = false;
  const CliOptions *cli_options = nullptr;
};

struct ScanRuntime {
  std::vector<ConnectedTarget> connected_targets;
  int last_error = 0;
  std::mutex connection_mutex;
  bool should_attempt_auth = false;
  std::vector<CredentialPair> auth_credentials;
  std::string credential_source;
  std::mutex auth_queue_mutex;
  std::condition_variable auth_queue_cv;
  std::deque<AuthTargetTask> auth_target_queue;
  std::atomic<bool> connect_scan_completed{false};
  std::atomic<bool> auth_succeeded{false};
  std::mutex auth_result_mutex;
  std::string successful_host;
  std::string successful_username;
  std::string successful_password;
  std::mutex results_file_mutex;
  std::vector<std::thread> auth_workers;
};

bool next_auth_target(const AuthWorkerContext &context,
                      AuthTargetTask &target_task) {
  std::unique_lock queue_lock(*context.auth_queue_mutex);
  context.auth_queue_cv->wait(queue_lock, [&context]() {
    return !context.auth_target_queue->empty() ||
           context.connect_scan_completed->load() ||
           context.auth_succeeded->load();
  });

  if (context.auth_succeeded->load()) {
    return false;
  }
  if (context.auth_target_queue->empty()) {
    return !context.connect_scan_completed->load();
  }

  target_task = std::move(context.auth_target_queue->front());
  context.auth_target_queue->pop_front();
  return true;
}

void attempt_auth_for_target(const AuthWorkerContext &context,
                             const AuthTargetTask &target_task) {
  {
    std::lock_guard results_lock(*context.results_file_mutex);
    if (context.results_file->is_open()) {
      (*context.results_file)
          << "[auth] scanning target=" << target_task.host << ":"
          << context.cli_options->target_port << "\n";
    }
  }

  for (size_t credential_index = 0;
       credential_index < context.auth_credentials->size();
       ++credential_index) {
    if (context.auth_succeeded->load()) {
      return;
    }
    if (context.cli_options->with_session &&
        context.session->auth_should_skip(target_task.target_index,
                                          credential_index)) {
      continue;
    }

    const auto &[username, password] =
        (*context.auth_credentials)[credential_index];
    const int auth_socket =
        connect_to_host_port(target_task.host, context.cli_options->target_port,
                             context.cli_options->auth_timeout_seconds,
                             context.cli_options->without_tor);
    if (auth_socket == -1) {
      if (context.cli_options->with_session) {
        context.session->auth_record(target_task.target_index,
                                     credential_index);
      }
      continue;
    }

    std::string target_username = username;
    std::string target_password = password;
    const bool target_auth_success = try_telnet_auth(
        auth_socket, target_task.host, context.cli_options->target_port,
        target_username, target_password, nullptr,
        context.cli_options->auth_timeout_seconds);
    close(auth_socket);

    if (context.cli_options->with_session) {
      context.session->auth_record(target_task.target_index, credential_index);
    }
    if (!target_auth_success) {
      continue;
    }

    if (const bool already_succeeded = context.auth_succeeded->exchange(true);
        !already_succeeded) {
      std::lock_guard lock(*context.auth_result_mutex);
      *context.successful_host = target_task.host;
      *context.successful_username = target_username;
      *context.successful_password = target_password;
      if (context.cli_options->with_session) {
        context.session->auth_record_success(target_task.host, target_username,
                                             target_password);
      }
    }
    {
      std::lock_guard results_lock(*context.results_file_mutex);
      if (context.results_file->is_open()) {
        (*context.results_file)
            << "[auth] target=" << target_task.host << ":"
            << context.cli_options->target_port << " auth_success=true\n";
      }
    }
    context.auth_queue_cv->notify_all();
    return;
  }
}

void run_auth_worker(const AuthWorkerContext &context) {
  while (true) {
    AuthTargetTask target_task;
    if (!next_auth_target(context, target_task)) {
      return;
    }
    attempt_auth_for_target(context, target_task);
  }
}

void run_connect_worker(const ConnectWorkerContext &context) {
  while (true) {
    const size_t target_index = context.next_target_index->fetch_add(1);
    if (target_index >= context.targets->size()) {
      return;
    }
    if (context.cli_options->with_session &&
        context.session->connect_should_skip(target_index)) {
      continue;
    }

    const std::string &target_host = (*context.targets)[target_index];
#ifdef DEBUG
    log_info("Trying " + target_host + ":" +
             std::to_string(context.cli_options->target_port));
#endif
    const int candidate_socket = connect_to_host_port(
        target_host, context.cli_options->target_port,
        context.cli_options->timeout_seconds, context.cli_options->without_tor);
    const int candidate_error = errno;
    const bool connected = candidate_socket != -1;

    {
      std::lock_guard lock(*context.connection_mutex);
      if (connected) {
        context.connected_targets->push_back({target_host, candidate_socket});
        if (context.should_attempt_auth) {
          std::lock_guard queue_lock(*context.auth_queue_mutex);
          context.auth_target_queue->push_back({target_index, target_host});
          context.auth_queue_cv->notify_one();
        }
      } else if (candidate_error != 0) {
        *context.last_error = candidate_error;
      } else {
        *context.last_error = ETIMEDOUT;
      }
    }

    if (context.cli_options->with_session) {
      context.session->connect_record(target_index, connected, target_host);
    }
    context.progress->increment();
  }
}

void close_open_sockets(std::vector<ConnectedTarget> &connected_targets) {
  for (ConnectedTarget &target : connected_targets) {
    if (target.socket_fd != -1) {
      close(target.socket_fd);
      target.socket_fd = -1;
    }
  }
}

int stream_socket_to_stdout(int sockfd) {
  std::string buffer(1024, '\0');
  ssize_t bytes_read = 0;
  while ((bytes_read = recv(sockfd, buffer.data(), buffer.size(), 0)) > 0) {
    log_stdout_chunk(
        std::string_view(buffer.data(), static_cast<size_t>(bytes_read)));
  }

  if (bytes_read == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
#ifdef DEBUG
    if (bytes_read != 0) {
      log_info("No more data before read timeout");
    }
#endif
    return 0;
  }

  log_error(std::string("Read error: ") + std::strerror(errno));
  return 1;
}

struct AppContext {
  std::string host_or_range;
  CliOptions cli_options;
  std::vector<std::string> targets;
  std::ofstream results_file;
  Session session;
  std::filesystem::path session_file_path;
  std::unordered_set<std::string> resumed_connected_hosts;
  ScanRuntime runtime;
};

void log_run_configuration(const AppContext &context) {
  log_info(
      "Target: " + context.host_or_range +
      ", expanded hosts: " + std::to_string(context.targets.size()) +
      ", port: " + std::to_string(context.cli_options.target_port) +
      ", timeout: " + std::to_string(context.cli_options.timeout_seconds) +
      "s, threads: " +
      std::to_string(context.cli_options.threads > 0
                         ? context.cli_options.threads
                         : static_cast<int>(context.targets.size())) +
      ", auth-threads: " +
      std::to_string(context.cli_options.auth_threads > 0
                         ? context.cli_options.auth_threads
                         : static_cast<int>(context.targets.size())) +
      ", auth-timeout: " +
      std::to_string(context.cli_options.auth_timeout_seconds) + "s" +
      ", with-auth: " +
      (context.cli_options.with_auth ? "enabled" : "disabled") + ", session: " +
      (context.cli_options.with_session ? "enabled" : "disabled") +
      ", tor: " + (context.cli_options.without_tor ? "disabled" : "enabled"));
}

bool initialize_results_file(AppContext &context) {
  if (context.cli_options.save_results_path.empty()) {
    return true;
  }

  context.results_file.open(context.cli_options.save_results_path,
                            std::ios::out | std::ios::trunc);
  if (!context.results_file.is_open()) {
    log_error("Failed to open results file '" +
              context.cli_options.save_results_path + "'");
    return false;
  }

  context.results_file << "target=" << context.host_or_range << "\n";
  context.results_file << "port=" << context.cli_options.target_port << "\n";
  context.results_file << "timeout_seconds="
                       << context.cli_options.timeout_seconds << "\n";
  context.results_file << "with_auth="
                       << (context.cli_options.with_auth ? "true" : "false")
                       << "\n";
  context.results_file << "auth_threads=" << context.cli_options.auth_threads
                       << "\n";
  context.results_file << "auth_timeout_seconds="
                       << context.cli_options.auth_timeout_seconds << "\n";
  context.results_file << "without_tor="
                       << (context.cli_options.without_tor ? "true" : "false")
                       << "\n";
  return true;
}

int initialize_session_state(AppContext &context) {
  if (!context.cli_options.with_session) {
    return -1;
  }
  if (!ensure_sessions_dir_exists()) {
    log_error("Failed to initialize session directory '~/.hydra-cli/sessions'");
    return 1;
  }

  const std::string session_key =
      build_session_key(context.host_or_range, context.cli_options);
  context.session_file_path = get_session_file_path(session_key);
  if (!context.session.open(context.session_file_path, session_key,
                            context.targets.size())) {
    log_error("Failed to initialize session state file '" +
              context.session_file_path.string() + "'");
    return 1;
  }

  const std::vector<std::string> previous_hosts =
      context.session.connected_hosts();
  context.resumed_connected_hosts.insert(previous_hosts.begin(),
                                         previous_hosts.end());

  const size_t pending = context.session.connect_pending_count();
  if (const size_t completed = context.targets.size() - pending;
      completed > 0) {
    log_info("Resuming session: " + std::to_string(completed) + " of " +
             std::to_string(context.targets.size()) +
             " host(s) already scanned, " +
             std::to_string(previous_hosts.size()) +
             " previous connection(s) recorded");
  }

  if (!context.session.auth_succeeded()) {
    return -1;
  }

  const std::string saved_host = context.session.auth_success_host();
  const std::string saved_user = context.session.auth_success_username();
  const std::string saved_pass = context.session.auth_success_password();
  log_info("Resuming completed session: telnet auth previously succeeded on " +
           saved_host + ":" + std::to_string(context.cli_options.target_port));
  if (context.results_file.is_open()) {
    context.results_file << "auth_status=success\n";
    context.results_file << "auth_host=" << saved_host << "\n";
    context.results_file << "auth_username=" << saved_user << "\n";
    context.results_file << "auth_password=" << saved_pass << "\n";
    context.results_file << "resumed_from_session=true\n";
  }
  context.session.clear();
  return 0;
}

void initialize_scan_runtime(AppContext &context) {
  context.runtime.should_attempt_auth =
      context.cli_options.with_auth && context.cli_options.target_port == 23;
  context.runtime.auth_credentials =
      context.cli_options.auth_combinations.empty()
          ? std::vector<CredentialPair>(k_default_telnet_credentials.begin(),
                                        k_default_telnet_credentials.end())
          : context.cli_options.auth_combinations;
  context.runtime.credential_source =
      context.cli_options.auth_combinations.empty() ? "default" : "custom";
}

void start_auth_workers(AppContext &context) {
  if (!context.runtime.should_attempt_auth) {
    return;
  }

  log_info("Attempting telnet authentication using " +
           context.runtime.credential_source + " credentials while scanning");
  if (context.cli_options.with_session &&
      !context.session.auth_init(context.targets.size(),
                                 context.runtime.auth_credentials.size())) {
    log_error("Failed to persist auth session state to '" +
              context.session_file_path.string() + "'");
  }

  const auto requested_auth_threads = static_cast<size_t>(
      context.cli_options.auth_threads > 0 ? context.cli_options.auth_threads
                                           : context.targets.size());
  const size_t auth_worker_count =
      std::min(context.targets.size(), requested_auth_threads);
  context.runtime.auth_workers.reserve(auth_worker_count);
  AuthWorkerContext auth_context{&context.runtime.auth_queue_mutex,
                                 &context.runtime.auth_queue_cv,
                                 &context.runtime.auth_target_queue,
                                 &context.runtime.connect_scan_completed,
                                 &context.runtime.auth_succeeded,
                                 &context.runtime.auth_result_mutex,
                                 &context.runtime.successful_host,
                                 &context.runtime.successful_username,
                                 &context.runtime.successful_password,
                                 &context.runtime.results_file_mutex,
                                 &context.results_file,
                                 &context.runtime.auth_credentials,
                                 &context.session,
                                 &context.cli_options};
  for (size_t worker_index = 0; worker_index < auth_worker_count;
       ++worker_index) {
    context.runtime.auth_workers.emplace_back(run_auth_worker,
                                              std::cref(auth_context));
  }
}

void run_connection_scan(AppContext &context) {
  std::vector<std::thread> workers;
  const auto requested_threads = static_cast<size_t>(
      context.cli_options.threads > 0 ? context.cli_options.threads
                                      : context.targets.size());
  const size_t worker_count =
      std::min(context.targets.size(), requested_threads);
  workers.reserve(worker_count);
  std::atomic<size_t> next_target_index(0);
  const size_t connect_initial_pending =
      context.cli_options.with_session ? context.session.connect_pending_count()
                                       : context.targets.size();
  ProgressIndicator progress;
  progress.start(connect_initial_pending, "checking hosts");
  ConnectWorkerContext connect_context{&progress,
                                       &context.runtime.connection_mutex,
                                       &context.runtime.connected_targets,
                                       &context.runtime.last_error,
                                       &context.targets,
                                       &next_target_index,
                                       &context.session,
                                       &context.runtime.auth_queue_mutex,
                                       &context.runtime.auth_target_queue,
                                       &context.runtime.auth_queue_cv,
                                       context.runtime.should_attempt_auth,
                                       &context.cli_options};

  for (size_t worker_index = 0; worker_index < worker_count; ++worker_index) {
    workers.emplace_back(run_connect_worker, std::cref(connect_context));
  }
  for (std::thread &worker : workers) {
    worker.join();
  }

  context.runtime.connect_scan_completed.store(true);
  context.runtime.auth_queue_cv.notify_all();
  progress.stop("done");
}

void finalize_connected_targets(AppContext &context) {
  if (!context.cli_options.with_session) {
    return;
  }
  for (const std::string &previous_host : context.resumed_connected_hosts) {
    const bool already_present =
        std::any_of(context.runtime.connected_targets.begin(),
                    context.runtime.connected_targets.end(),
                    [&previous_host](const ConnectedTarget &target) {
                      return target.host == previous_host;
                    });
    if (!already_present) {
      context.runtime.connected_targets.push_back({previous_host, -1});
    }
  }
  context.session.connect_finalize();
}

int handle_empty_connections(AppContext &context) {
  if (!context.runtime.connected_targets.empty()) {
    return -1;
  }
  if (context.cli_options.with_session) {
    context.session.clear();
  }
  errno = context.runtime.last_error;
  const std::string connection_mode = context.cli_options.without_tor
                                          ? "direct connection"
                                          : "Tor SOCKS5 proxy 127.0.0.1:9050";
  log_error("Failed to connect to all targets in '" + context.host_or_range +
            "' using " + connection_mode + " (" + std::strerror(errno) + ")");
  if (context.results_file.is_open()) {
    context.results_file << "connection_status=failed\n";
    context.results_file << "error=" << std::strerror(errno) << "\n";
  }
  return 1;
}

void write_connection_success(AppContext &context) {
#ifdef DEBUG
  log_info("Connected to " +
           std::to_string(context.runtime.connected_targets.size()) +
           " target(s) on port " +
           std::to_string(context.cli_options.target_port) +
           (context.cli_options.without_tor ? " directly" : " through Tor"));
#endif
  if (!context.results_file.is_open()) {
    return;
  }
  context.results_file << "connection_status=success\n";
  context.results_file << "connected_targets="
                       << context.runtime.connected_targets.size() << "\n";
  for (const ConnectedTarget &target : context.runtime.connected_targets) {
    context.results_file << "connected_host=" << target.host << "\n";
  }
}

int handle_auth_phase(AppContext &context) {
  if (!context.runtime.should_attempt_auth) {
    return -1;
  }
  for (std::thread &auth_worker : context.runtime.auth_workers) {
    auth_worker.join();
  }

  if (!context.runtime.auth_succeeded.load()) {
    log_error("Telnet authentication attempt failed");
    if (context.results_file.is_open()) {
      context.results_file << "auth_status=failed\n";
    }
    close_open_sockets(context.runtime.connected_targets);
    if (context.cli_options.with_session) {
      context.session.clear();
    }
    return 1;
  }

  log_info("Telnet authentication succeeded on " +
           context.runtime.successful_host + ":" +
           std::to_string(context.cli_options.target_port));
  if (context.results_file.is_open()) {
    context.results_file << "auth_status=success\n";
    context.results_file << "auth_host=" << context.runtime.successful_host
                         << "\n";
    context.results_file << "auth_username="
                         << context.runtime.successful_username << "\n";
    context.results_file << "auth_password="
                         << context.runtime.successful_password << "\n";
  }
  if (context.cli_options.with_session) {
    context.session.clear();
  }
  return 0;
}

int handle_single_connection_output(AppContext &context) {
  const std::string connected_host =
      context.runtime.connected_targets.front().host;
  const int sockfd = context.runtime.connected_targets.front().socket_fd;
  for (size_t index = 1; index < context.runtime.connected_targets.size();
       ++index) {
    if (context.runtime.connected_targets[index].socket_fd != -1) {
      close(context.runtime.connected_targets[index].socket_fd);
      context.runtime.connected_targets[index].socket_fd = -1;
    }
  }

  log_stdout_chunk(connected_host + ":" +
                   std::to_string(context.cli_options.target_port) + " ");
  if (stream_socket_to_stdout(sockfd) != 0) {
    close(sockfd);
    return 1;
  }

  flush_stdout_buffer();
  if (context.results_file.is_open()) {
    context.results_file << "read_status=completed\n";
  }
  close(sockfd);
  if (context.cli_options.with_session) {
    context.session.clear();
  }
  log_info("Connection closed");
  return 0;
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

  AppContext context;
  context.host_or_range = argv[1];
  if (!parse_cli_options(argc, argv, context.cli_options)) {
    print_usage(argv[0]);
    return 1;
  }
  if (!parse_host_range(context.host_or_range, context.targets)) {
    context.targets.push_back(context.host_or_range);
  }

  log_run_configuration(context);
  if (!initialize_results_file(context)) {
    return 1;
  }
  if (const int session_init_result = initialize_session_state(context);
      session_init_result != -1) {
    return session_init_result;
  }

  initialize_scan_runtime(context);
  start_auth_workers(context);
  run_connection_scan(context);
  finalize_connected_targets(context);
  if (const int empty_result = handle_empty_connections(context);
      empty_result != -1) {
    return empty_result;
  }
  write_connection_success(context);
  if (const int auth_result = handle_auth_phase(context); auth_result != -1) {
    return auth_result;
  }
  return handle_single_connection_output(context);
}
