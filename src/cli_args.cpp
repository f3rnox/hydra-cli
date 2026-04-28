#include "./cli_args.hpp"

#include <iostream>
#include <sstream>
#include <string>

namespace {

bool parse_octet(const std::string &value, int &octet) {
  if (value.empty()) {
    return false;
  }

  for (const char c : value) {
    if (c < '0' || c > '9') {
      return false;
    }
  }

  try {
    octet = std::stoi(value);
  } catch (...) {
    return false;
  }

  return octet >= 0 && octet <= 255;
}

} // namespace

void print_usage(const char *program_name) {
  std::cerr << "Usage: " << program_name
            << " <target-host-or-range> [--timeout-seconds N] [--port P] "
               "[--threads N] [--with-auth] "
               "[--without-tor]\n"
            << "Examples:\n"
            << "  " << program_name
            << " example.com --port 22 --timeout-seconds 5\n"
            << "  " << program_name
            << " 127.0.0.1-255 --timeout-seconds 2 --port 443 --threads 32\n"
            << "  " << program_name << " 192.168.1.10 --port 23 --with-auth\n"
            << "  " << program_name << " 10.0.0.5 --port 80 --without-tor\n";
}

bool parse_cli_options(int argc, char **argv, CliOptions &options) {
  if (argc == 2) {
    return true;
  }

  for (int i = 2; i < argc;) {
    const std::string flag = argv[i];

    if (flag == "--with-auth") {
      options.with_auth = true;
      ++i;
      continue;
    }

    if (flag == "--without-tor") {
      options.without_tor = true;
      ++i;
      continue;
    }

    if (i + 1 >= argc) {
      return false;
    }

    const std::string value = argv[i + 1];

    if (flag == "--timeout-seconds") {
      try {
        options.timeout_seconds = std::stoi(value);
        if (options.timeout_seconds <= 0) {
          return false;
        }
      } catch (...) {
        return false;
      }
      i += 2;
      continue;
    }

    if (flag == "--port") {
      try {
        options.target_port = std::stoi(value);
        if (options.target_port <= 0 || options.target_port > 65535) {
          return false;
        }
      } catch (...) {
        return false;
      }
      i += 2;
      continue;
    }

    if (flag == "--threads") {
      try {
        options.threads = std::stoi(value);
        if (options.threads <= 0) {
          return false;
        }
      } catch (...) {
        return false;
      }
      i += 2;
      continue;
    }

    return false;
  }

  return true;
}

bool parse_host_range(const std::string &input,
                      std::vector<std::string> &targets) {
  const size_t dash_pos = input.rfind('-');
  const size_t dot_pos = input.rfind('.');
  if (dash_pos == std::string::npos || dot_pos == std::string::npos ||
      dash_pos <= dot_pos) {
    return false;
  }

  const std::string prefix = input.substr(0, dot_pos + 1);
  const std::string start_octet_string =
      input.substr(dot_pos + 1, dash_pos - dot_pos - 1);
  const std::string end_octet_string = input.substr(dash_pos + 1);

  int start_octet = 0;
  int end_octet = 0;
  if (!parse_octet(start_octet_string, start_octet) ||
      !parse_octet(end_octet_string, end_octet)) {
    return false;
  }
  if (start_octet > end_octet) {
    return false;
  }

  std::stringstream prefix_stream(prefix.substr(0, prefix.size() - 1));
  std::string part;
  int part_count = 0;
  while (std::getline(prefix_stream, part, '.')) {
    int octet = 0;
    if (!parse_octet(part, octet)) {
      return false;
    }
    ++part_count;
  }
  if (part_count != 3) {
    return false;
  }

  targets.reserve(static_cast<size_t>(end_octet - start_octet + 1));
  for (int octet = start_octet; octet <= end_octet; ++octet) {
    targets.push_back(prefix + std::to_string(octet));
  }
  return true;
}
