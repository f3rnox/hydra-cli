#pragma once

#include <string>
#include <vector>

void print_usage(const char* program_name);
bool parse_timeout(int argc, char** argv, int& timeout_seconds);
bool parse_host_range(const std::string& input, std::vector<std::string>& targets);
