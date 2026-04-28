#include "./cli_args.hpp"
#include "./logging.hpp"

#include <array>
#include <limits>
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

bool parse_octet_range(const std::string &value, int &start_octet,
                       int &end_octet) {
  if (value.empty()) {
    return false;
  }

  const size_t dash_pos = value.find('-');
  if (dash_pos == std::string::npos) {
    if (!parse_octet(value, start_octet)) {
      return false;
    }
    end_octet = start_octet;
    return true;
  }

  if (value.find('-', dash_pos + 1) != std::string::npos) {
    return false;
  }

  const std::string start_string = value.substr(0, dash_pos);
  if (const std::string end_string = value.substr(dash_pos + 1);
      !parse_octet(start_string, start_octet) ||
      !parse_octet(end_string, end_octet)) {
    return false;
  }

  return start_octet <= end_octet;
}

bool parse_auth_combo(const std::string &value, std::string &username,
                      std::string &password) {
  const size_t delimiter_position = value.find(':');
  if (delimiter_position == std::string::npos) {
    return false;
  }

  username = value.substr(0, delimiter_position);
  password = value.substr(delimiter_position + 1);
  return !username.empty();
}

} // namespace

void print_usage(const char *program_name) {
  const std::string usage =
      std::string("Usage: ") + program_name +
      " <target-host-or-range> [--timeout-seconds N] [--port P] [--threads N] "
      "[--auth-threads N] [--auth-timeout N] [--save-results FILE] "
      "[--auth-combo USER:PASS] [--with-auth] "
      "[--with-session] [--without-tor]\n"
      "Examples:\n"
      "  " +
      program_name +
      " example.com --port 22 --timeout-seconds 5\n"
      "  " +
      program_name +
      " 127.0.0.1-255 --timeout-seconds 2 --port 443 --threads 32\n"
      "  " +
      program_name +
      " 192.168.1.10-20 --port 23 --with-auth --auth-threads 8\n"
      "  " +
      program_name +
      " 192.168.1.10-20 --port 23 --with-auth --auth-timeout 2\n"
      "  " +
      program_name +
      " 192.168.1.10 --port 23 --with-auth --auth-combo admin:admin\n"
      "  " +
      program_name +
      " 192.168.1.10 --port 23 --save-results results.txt\n"
      "  " +
      program_name +
      " 192.168.1.10 --port 23 --with-auth\n"
      "  " +
      program_name +
      " 10.0.0.5 --port 22 --with-session\n"
      "  " +
      program_name + " 10.0.0.5 --port 80 --without-tor";
  log_stderr_line(usage);
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

    if (flag == "--with-session") {
      options.with_session = true;
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

    if (flag == "--auth-threads") {
      try {
        options.auth_threads = std::stoi(value);
        if (options.auth_threads <= 0) {
          return false;
        }
      } catch (...) {
        return false;
      }
      i += 2;
      continue;
    }

    if (flag == "--auth-timeout") {
      try {
        options.auth_timeout_seconds = std::stoi(value);
        if (options.auth_timeout_seconds <= 0) {
          return false;
        }
      } catch (...) {
        return false;
      }
      i += 2;
      continue;
    }

    if (flag == "--save-results") {
      if (value.empty()) {
        return false;
      }
      options.save_results_path = value;
      i += 2;
      continue;
    }

    if (flag == "--auth-combo") {
      std::string username;
      std::string password;
      if (!parse_auth_combo(value, username, password)) {
        return false;
      }
      options.auth_combinations.push_back({username, password});
      i += 2;
      continue;
    }

    return false;
  }

  return true;
}

bool parse_host_range(const std::string &input,
                      std::vector<std::string> &targets) {
  std::array<std::string, 4> octet_parts;
  std::stringstream input_stream(input);
  std::string part;
  size_t part_count = 0;
  while (std::getline(input_stream, part, '.')) {
    if (part_count >= octet_parts.size()) {
      return false;
    }
    octet_parts[part_count] = part;
    ++part_count;
  }
  if (part_count != octet_parts.size()) {
    return false;
  }

  std::array<std::pair<int, int>, 4> octet_ranges{};
  bool has_range = false;
  for (size_t index = 0; index < octet_parts.size(); ++index) {
    int start_octet = 0;
    int end_octet = 0;
    if (!parse_octet_range(octet_parts[index], start_octet, end_octet)) {
      return false;
    }
    if (start_octet != end_octet) {
      has_range = true;
    }
    octet_ranges[index] = {start_octet, end_octet};
  }

  if (!has_range) {
    return false;
  }

  size_t total_targets = 1;
  for (const auto &[start_octet, end_octet] : octet_ranges) {
    const size_t octet_count = static_cast<size_t>(end_octet - start_octet + 1);
    if (octet_count == 0) {
      return false;
    }
    if (total_targets > std::numeric_limits<size_t>::max() / octet_count) {
      total_targets = 0;
      break;
    }
    total_targets *= octet_count;
  }

  if (total_targets > 0) {
    targets.reserve(total_targets);
  }

  for (int octet0 = octet_ranges[0].first; octet0 <= octet_ranges[0].second;
       ++octet0) {
    for (int octet1 = octet_ranges[1].first; octet1 <= octet_ranges[1].second;
         ++octet1) {
      for (int octet2 = octet_ranges[2].first; octet2 <= octet_ranges[2].second;
           ++octet2) {
        for (int octet3 = octet_ranges[3].first;
             octet3 <= octet_ranges[3].second; ++octet3) {
          targets.push_back(
              std::to_string(octet0) + "." + std::to_string(octet1) + "." +
              std::to_string(octet2) + "." + std::to_string(octet3));
        }
      }
    }
  }

  return true;
}
