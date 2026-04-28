#pragma once

#include <string>
#include <utility>
#include <vector>

struct CliOptions {
  int timeout_seconds = 5;
  int auth_timeout_seconds = 5;
  int target_port = 22;
  int threads = 0;
  int auth_threads = 0;
  std::string save_results_path;
  std::vector<std::pair<std::string, std::string>> auth_combinations;
  bool with_auth = false;
  bool with_session = false;
  bool without_tor = false;
};

void print_usage(const char *program_name);
bool parse_cli_options(int argc, char **argv, CliOptions &options);
bool parse_host_range(const std::string &input,
                      std::vector<std::string> &targets);
