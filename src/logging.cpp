#include "./logging.hpp"

#include <iostream>

void log_info(const std::string& message) {
  std::cout << "[info] " << message << "\n";
}

void log_error(const std::string& message) {
  std::cerr << "[error] " << message << "\n";
}
