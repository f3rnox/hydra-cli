#include "./cli_args.hpp"
#include "./logging.hpp"

#include <array>
#include <exception>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>

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
  } catch (const std::invalid_argument &) {
    return false;
  } catch (const std::out_of_range &) {
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

bool parse_auth_combo(std::string_view value, std::string &username,
                      std::string &password) {
  const size_t delimiter_position = value.find(':');
  if (delimiter_position == std::string_view::npos) {
    return false;
  }

  username = value.substr(0, delimiter_position);
  password = value.substr(delimiter_position + 1);
  return !username.empty();
}

bool parse_positive_integer(std::string_view value, int &target) {
  try {
    target = std::stoi(std::string(value));
    return target > 0;
  } catch (const std::invalid_argument &) {
    return false;
  } catch (const std::out_of_range &) {
    return false;
  }
}

bool parse_port(std::string_view value, int &target_port) {
  if (!parse_positive_integer(value, target_port)) {
    return false;
  }
  return target_port <= 65535;
}

bool parse_value_option(std::string_view flag, std::string_view value,
                        CliOptions &options) {
  if (flag == "--timeout-seconds") {
    return parse_positive_integer(value, options.timeout_seconds);
  }
  if (flag == "--port") {
    return parse_port(value, options.target_port);
  }
  if (flag == "--threads") {
    return parse_positive_integer(value, options.threads);
  }
  if (flag == "--auth-threads") {
    return parse_positive_integer(value, options.auth_threads);
  }
  if (flag == "--auth-timeout") {
    return parse_positive_integer(value, options.auth_timeout_seconds);
  }
  if (flag == "--save-results") {
    if (value.empty()) {
      return false;
    }
    options.save_results_path = value;
    return true;
  }
  if (flag == "--auth-combo") {
    std::string username;
    std::string password;
    if (!parse_auth_combo(value, username, password)) {
      return false;
    }
    options.auth_combinations.emplace_back(username, password);
    return true;
  }
  return false;
}

bool is_toggle_option(std::string_view flag, CliOptions &options) {
  if (flag == "--with-auth") {
    options.with_auth = true;
    return true;
  }
  if (flag == "--without-tor") {
    options.without_tor = true;
    return true;
  }
  if (flag == "--with-session") {
    options.with_session = true;
    return true;
  }
  return false;
}

void append_targets_from_ranges(
    const std::array<std::pair<int, int>, 4> &octet_ranges, size_t index,
    std::array<int, 4> &selected_octets, std::vector<std::string> &targets) {
  if (index == selected_octets.size()) {
    targets.push_back(std::to_string(selected_octets[0]) + "." +
                      std::to_string(selected_octets[1]) + "." +
                      std::to_string(selected_octets[2]) + "." +
                      std::to_string(selected_octets[3]));
    return;
  }

  for (int value = octet_ranges[index].first;
       value <= octet_ranges[index].second; ++value) {
    selected_octets[index] = value;
    append_targets_from_ranges(octet_ranges, index + 1, selected_octets,
                               targets);
  }
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

    if (is_toggle_option(flag, options)) {
      ++i;
      continue;
    }

    if (i + 1 >= argc) {
      return false;
    }

    if (const std::string value = argv[i + 1];
        !parse_value_option(flag, value, options)) {
      return false;
    }
    i += 2;
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
    const auto octet_count = static_cast<size_t>(end_octet - start_octet + 1);
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

  std::array<int, 4> selected_octets{};
  append_targets_from_ranges(octet_ranges, 0, selected_octets, targets);

  return true;
}
