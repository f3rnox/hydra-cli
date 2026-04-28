#include "./cli_args.hpp"
#include "./config.hpp"
#include "./logging.hpp"
#include "./network.hpp"
#include "./progress.hpp"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

int main(int argc, char** argv) {
  log_info("hydra-cli started");
  if (argc != 2 && argc != 4) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string host_or_range = argv[1];
  int timeout_seconds = 5;
  if (!parse_timeout(argc, argv, timeout_seconds)) {
    print_usage(argv[0]);
    return 1;
  }

  std::vector<std::string> targets;
  if (!parse_host_range(host_or_range, targets)) {
    targets.push_back(host_or_range);
  }

  log_info("Target: " + host_or_range + ", expanded hosts: " + std::to_string(targets.size()) +
           ", timeout: " + std::to_string(timeout_seconds) + "s");

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
                          timeout_seconds]() {
#ifdef DEBUG
      log_info("Trying " + target_host + ":22");
#endif
      const int candidate_socket = connect_to_host_port_22(target_host, timeout_seconds);
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
    log_error("Failed to connect to all targets in '" + host_or_range +
              "' through Tor SOCKS5 proxy 127.0.0.1:9050 (" + std::strerror(errno) + ")");
    return 1;
  }

#ifdef DEBUG
  log_info("Connected to " + connected_host + ":22 through Tor");
#endif
  std::cout << connected_host << ":22 ";

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
