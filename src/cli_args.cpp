#include "./cli_args.hpp"

#include <iostream>
#include <sstream>
#include <string>

namespace {

bool parse_octet(const std::string& value, int& octet) {
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

}  // namespace

void print_usage(const char* program_name) {
  std::cerr << "Usage: " << program_name << " <target-host-or-range> [--timeout-seconds N]\n"
            << "Examples:\n"
            << "  " << program_name << " example.com --timeout-seconds 5\n"
            << "  " << program_name << " 127.0.0.1-255 --timeout-seconds 2\n";
}

bool parse_timeout(int argc, char** argv, int& timeout_seconds) {
  timeout_seconds = 5;

  if (argc == 2) {
    return true;
  }

  if (argc == 4 && std::string(argv[2]) == "--timeout-seconds") {
    try {
      timeout_seconds = std::stoi(argv[3]);
      if (timeout_seconds <= 0) {
        return false;
      }
      return true;
    } catch (...) {
      return false;
    }
  }

  return false;
}

bool parse_host_range(const std::string& input, std::vector<std::string>& targets) {
  const size_t dash_pos = input.rfind('-');
  const size_t dot_pos = input.rfind('.');
  if (dash_pos == std::string::npos || dot_pos == std::string::npos || dash_pos <= dot_pos) {
    return false;
  }

  const std::string prefix = input.substr(0, dot_pos + 1);
  const std::string start_octet_string = input.substr(dot_pos + 1, dash_pos - dot_pos - 1);
  const std::string end_octet_string = input.substr(dash_pos + 1);

  int start_octet = 0;
  int end_octet = 0;
  if (!parse_octet(start_octet_string, start_octet) || !parse_octet(end_octet_string, end_octet)) {
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
