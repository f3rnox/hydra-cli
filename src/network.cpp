#include "./network.hpp"

#include "./config.hpp"
#include "./logging.hpp"

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <netdb.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

bool set_socket_timeouts(int sockfd, int timeout_seconds) {
  timeval timeout{};
  timeout.tv_sec = timeout_seconds;
  timeout.tv_usec = 0;
  const int recv_timeout_result =
      setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  const int send_timeout_result =
      setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  return recv_timeout_result == 0 && send_timeout_result == 0;
}

int connect_direct(const std::string &host, int target_port,
                   int timeout_seconds) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo *result = nullptr;
  const std::string target_port_string = std::to_string(target_port);
  if (const int get_addr_info_result = getaddrinfo(
          host.c_str(), target_port_string.c_str(), &hints, &result);
      get_addr_info_result != 0) {
    log_error("Failed to resolve target '" + host + ":" + target_port_string +
              "': " + gai_strerror(get_addr_info_result));
    return -1;
  }

  int sockfd = -1;
  for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
    sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sockfd == -1) {
      continue;
    }
    if (!set_socket_timeouts(sockfd, timeout_seconds)) {
      close(sockfd);
      sockfd = -1;
      continue;
    }
    if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(sockfd);
    sockfd = -1;
  }

  freeaddrinfo(result);
  return sockfd;
}

bool send_socks5_greeting(int sockfd) {
  const std::array<unsigned char, 3> greeting = {0x05, 0x01, 0x00};
  return send(sockfd, greeting.data(), greeting.size(), 0) ==
         static_cast<ssize_t>(greeting.size());
}

bool receive_socks5_method_selection(int sockfd) {
  std::array<unsigned char, 2> method_selection = {0, 0};
  if (recv(sockfd, method_selection.data(), method_selection.size(),
           MSG_WAITALL) != static_cast<ssize_t>(method_selection.size())) {
    return false;
  }
  return method_selection[0] == 0x05 && method_selection[1] == 0x00;
}

bool send_socks5_connect_request(int sockfd, std::string_view host,
                                 int target_port) {
  if (host.size() > 255) {
    errno = EINVAL;
    return false;
  }

  std::string request;
  request.reserve(7 + host.size());
  request.push_back(static_cast<char>(0x05));
  request.push_back(static_cast<char>(0x01));
  request.push_back(static_cast<char>(0x00));
  request.push_back(static_cast<char>(0x03));
  request.push_back(static_cast<char>(host.size()));
  request.append(host.data(), host.size());
  request.push_back(static_cast<char>((target_port >> 8) & 0xFF));
  request.push_back(static_cast<char>(target_port & 0xFF));

  return send(sockfd, request.data(), request.size(), 0) ==
         static_cast<ssize_t>(request.size());
}

bool receive_socks5_connect_reply(int sockfd) {
  std::array<unsigned char, 4> reply_header = {0, 0, 0, 0};
  if (recv(sockfd, reply_header.data(), reply_header.size(), MSG_WAITALL) !=
      static_cast<ssize_t>(reply_header.size())) {
    return false;
  }
  if (reply_header[0] != 0x05 || reply_header[1] != 0x00) {
    errno = ECONNREFUSED;
    return false;
  }

  size_t address_length = 0;
  if (reply_header[3] == 0x01) {
    address_length = 4;
  } else if (reply_header[3] == 0x04) {
    address_length = 16;
  } else if (reply_header[3] == 0x03) {
    unsigned char domain_length = 0;
    if (recv(sockfd, &domain_length, 1, MSG_WAITALL) != 1) {
      return false;
    }
    address_length = domain_length;
  } else {
    errno = EPROTO;
    return false;
  }

  if (address_length > 0) {
    std::string skip_address(address_length, '\0');
    if (recv(sockfd, skip_address.data(), skip_address.size(), MSG_WAITALL) !=
        static_cast<ssize_t>(skip_address.size())) {
      return false;
    }
  }

  if (std::array<unsigned char, 2> bound_port = {0, 0};
      recv(sockfd, bound_port.data(), bound_port.size(), MSG_WAITALL) !=
      static_cast<ssize_t>(bound_port.size())) {
    return false;
  }

  return true;
}

int connect_via_tor(const std::string &host, int target_port,
                    int timeout_seconds) {
  const std::string tor_proxy_host = "127.0.0.1";
  const std::string tor_proxy_port = "9050";
#ifdef DEBUG
  log_info("Resolving Tor proxy " + tor_proxy_host + ":" + tor_proxy_port);
#endif

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo *result = nullptr;
  if (const int get_addr_info_result = getaddrinfo(
          tor_proxy_host.c_str(), tor_proxy_port.c_str(), &hints, &result);
      get_addr_info_result != 0) {
    log_error("Failed to resolve Tor proxy '" + tor_proxy_host + ":" +
              tor_proxy_port + "': " + gai_strerror(get_addr_info_result));
    return -1;
  }

  int sockfd = -1;
  for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
#ifdef DEBUG
    log_info("Attempting TCP connection to Tor proxy");
#endif
    sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sockfd == -1) {
      continue;
    }
    if (!set_socket_timeouts(sockfd, timeout_seconds) ||
        connect(sockfd, rp->ai_addr, rp->ai_addrlen) != 0 ||
        !send_socks5_greeting(sockfd) ||
        !receive_socks5_method_selection(sockfd) ||
        !send_socks5_connect_request(sockfd, host, target_port) ||
        !receive_socks5_connect_reply(sockfd)) {
      close(sockfd);
      sockfd = -1;
      continue;
    }
#ifdef DEBUG
    log_info("SOCKS5 tunnel established");
#endif
    break;
  }

  freeaddrinfo(result);
  return sockfd;
}

} // namespace

int connect_to_host_port(const std::string &host, int target_port,
                         int timeout_seconds, bool without_tor) {
  if (without_tor) {
    return connect_direct(host, target_port, timeout_seconds);
  }
  return connect_via_tor(host, target_port, timeout_seconds);
}
