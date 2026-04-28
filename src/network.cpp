#include "./network.hpp"

#include "./config.hpp"
#include "./logging.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int connect_to_host_port_22(const std::string& host, int timeout_seconds) {
  const std::string tor_proxy_host = "127.0.0.1";
  const std::string tor_proxy_port = "9050";
#ifdef DEBUG
  log_info("Resolving Tor proxy " + tor_proxy_host + ":" + tor_proxy_port);
#endif

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo* result = nullptr;
  const int get_addr_info_result =
      getaddrinfo(tor_proxy_host.c_str(), tor_proxy_port.c_str(), &hints, &result);
  if (get_addr_info_result != 0) {
    log_error("Failed to resolve Tor proxy '" + tor_proxy_host + ":" + tor_proxy_port +
              "': " + gai_strerror(get_addr_info_result));
    return -1;
  }

  int sockfd = -1;
  for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
#ifdef DEBUG
    log_info("Attempting TCP connection to Tor proxy");
#endif
    sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sockfd == -1) {
      continue;
    }

    timeval timeout{};
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != 0) {
      close(sockfd);
      sockfd = -1;
      continue;
    }

#ifdef DEBUG
    log_info("Connected to Tor proxy, starting SOCKS5 handshake");
#endif

    const unsigned char greeting[] = {0x05, 0x01, 0x00};
    if (send(sockfd, greeting, sizeof(greeting), 0) != static_cast<ssize_t>(sizeof(greeting))) {
      close(sockfd);
      sockfd = -1;
      continue;
    }

    unsigned char method_selection[2];
    if (recv(sockfd, method_selection, sizeof(method_selection), MSG_WAITALL) !=
        static_cast<ssize_t>(sizeof(method_selection))) {
      close(sockfd);
      sockfd = -1;
      continue;
    }

    if (method_selection[0] != 0x05 || method_selection[1] != 0x00) {
      errno = ECONNREFUSED;
      close(sockfd);
      sockfd = -1;
      continue;
    }

    if (host.size() > 255) {
      errno = EINVAL;
      close(sockfd);
      sockfd = -1;
      continue;
    }

    std::string request;
    request.reserve(7 + host.size());
    request.push_back(static_cast<char>(0x05));
    request.push_back(static_cast<char>(0x01));
    request.push_back(static_cast<char>(0x00));
    request.push_back(static_cast<char>(0x03));
    request.push_back(static_cast<char>(host.size()));
    request.append(host);
    request.push_back(static_cast<char>(0x00));
    request.push_back(static_cast<char>(0x16));

    if (send(sockfd, request.data(), request.size(), 0) != static_cast<ssize_t>(request.size())) {
      close(sockfd);
      sockfd = -1;
      continue;
    }
#ifdef DEBUG
    log_info("SOCKS5 connect request sent for " + host + ":22");
#endif

    unsigned char reply_header[4];
    if (recv(sockfd, reply_header, sizeof(reply_header), MSG_WAITALL) !=
        static_cast<ssize_t>(sizeof(reply_header))) {
      close(sockfd);
      sockfd = -1;
      continue;
    }

    if (reply_header[0] != 0x05 || reply_header[1] != 0x00) {
      errno = ECONNREFUSED;
      close(sockfd);
      sockfd = -1;
      continue;
    }

    size_t address_length = 0;
    if (reply_header[3] == 0x01) {
      address_length = 4;
    } else if (reply_header[3] == 0x04) {
      address_length = 16;
    } else if (reply_header[3] == 0x03) {
      unsigned char domain_length = 0;
      if (recv(sockfd, &domain_length, 1, MSG_WAITALL) != 1) {
        close(sockfd);
        sockfd = -1;
        continue;
      }
      address_length = domain_length;
    } else {
      errno = EPROTO;
      close(sockfd);
      sockfd = -1;
      continue;
    }

    if (address_length > 0) {
      std::string skip_address(address_length, '\0');
      if (recv(sockfd, skip_address.data(), skip_address.size(), MSG_WAITALL) !=
          static_cast<ssize_t>(skip_address.size())) {
        close(sockfd);
        sockfd = -1;
        continue;
      }
    }

    unsigned char bound_port[2];
    if (recv(sockfd, bound_port, sizeof(bound_port), MSG_WAITALL) !=
        static_cast<ssize_t>(sizeof(bound_port))) {
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
