#include "./cli_args.hpp"
#include "./config.hpp"
#include "./logging.hpp"
#include "./network.hpp"
#include "./progress.hpp"

#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <array>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {

bool send_telnet_line(int sockfd, const std::string& line) {
  const std::string payload = line + "\r\n";
  return send(sockfd, payload.data(), payload.size(), 0) == static_cast<ssize_t>(payload.size());
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

bool response_indicates_failed_auth(const std::string& response) {
  const std::string lower_response = [&response]() {
    std::string lowered = response;
    for (char& c : lowered) {
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

bool try_telnet_auth(int sockfd, std::string& successful_username, std::string& successful_password) {
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

  for (const auto& [username, password] : credentials) {
    std::cout << "[auth] trying username='" << username << "' password='" << password << "'\n";
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
      std::cout << "[auth] success username='" << successful_username << "' password='"
                << successful_password << "'\n";
      return true;
    }
  }

  return false;
}

}  // namespace

int main(int argc, char** argv) {
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

  log_info("Target: " + host_or_range + ", expanded hosts: " + std::to_string(targets.size()) +
           ", port: " + std::to_string(cli_options.target_port) +
           ", timeout: " + std::to_string(cli_options.timeout_seconds) +
           "s, with-auth: " + (cli_options.with_auth ? "enabled" : "disabled") +
           ", tor: " + (cli_options.without_tor ? "disabled" : "enabled"));

  int sockfd = -1;
  std::string connected_host;
  int last_error = 0;
  std::mutex connection_mutex;
  std::vector<std::thread> workers;
  workers.reserve(targets.size());
  ProgressIndicator progress;
  progress.start(targets.size(), "checking hosts");

  for (const std::string& target_host : targets) {
    workers.emplace_back([&progress,
                          &connection_mutex,
                          &connected_host,
                          &last_error,
                          &sockfd,
                          &target_host,
                          cli_options]() {
#ifdef DEBUG
      log_info("Trying " + target_host + ":" + std::to_string(cli_options.target_port));
#endif
      const int candidate_socket =
          connect_to_host_port(target_host, cli_options.target_port, cli_options.timeout_seconds,
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
      }

      progress.increment();
    });
  }

  for (std::thread& worker : workers) {
    worker.join();
  }
  progress.stop("done");

  if (sockfd == -1) {
    errno = last_error;
    const std::string connection_mode =
        cli_options.without_tor ? "direct connection" : "Tor SOCKS5 proxy 127.0.0.1:9050";
    log_error("Failed to connect to all targets in '" + host_or_range + "' using " +
              connection_mode + " (" + std::strerror(errno) + ")");
    return 1;
  }

#ifdef DEBUG
  log_info("Connected to " + connected_host + ":" + std::to_string(cli_options.target_port) +
           (cli_options.without_tor ? " directly" : " through Tor"));
#endif

  if (cli_options.with_auth && cli_options.target_port == 23) {
    log_info("Attempting telnet authentication using default credentials");
    std::string successful_username;
    std::string successful_password;
    if (!try_telnet_auth(sockfd, successful_username, successful_password)) {
      log_error("Telnet authentication attempt failed");
      close(sockfd);
      return 1;
    }
    close(sockfd);
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
  close(sockfd);
  log_info("Connection closed");
  return 0;
}
