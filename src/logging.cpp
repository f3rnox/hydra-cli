#include "./logging.hpp"

#include <iostream>
#include <mutex>
#include <string>
#include <string_view>

namespace {

std::mutex &console_mutex() {
  static std::mutex value;
  return value;
}

std::string &stdout_pending() {
  static std::string value;
  return value;
}

void write_stdout_unlocked(std::string_view text) {
  std::cout << text;
  std::cout.flush();
}

void write_stderr_unlocked(std::string_view text) {
  std::cerr << text;
  std::cerr.flush();
}

} // namespace

void log_info(std::string_view message) {
  std::lock_guard lock(console_mutex());
  write_stdout_unlocked(std::string("[info] ") + std::string(message) + "\n");
}

void log_error(std::string_view message) {
  std::lock_guard lock(console_mutex());
  write_stderr_unlocked(std::string("[error] ") + std::string(message) + "\n");
}

void log_stdout_line(std::string_view message) {
  std::lock_guard lock(console_mutex());
  write_stdout_unlocked(std::string(message) + "\n");
}

void log_stderr_line(std::string_view message) {
  std::lock_guard lock(console_mutex());
  write_stderr_unlocked(std::string(message) + "\n");
}

void log_stdout_chunk(std::string_view chunk) {
  std::lock_guard lock(console_mutex());
  std::string &pending = stdout_pending();
  pending.append(chunk);

  size_t newline_position = pending.find('\n');
  while (newline_position != std::string::npos) {
    const std::string complete_line = pending.substr(0, newline_position + 1);
    write_stdout_unlocked(complete_line);
    pending.erase(0, newline_position + 1);
    newline_position = pending.find('\n');
  }
}

void flush_stdout_buffer() {
  std::lock_guard lock(console_mutex());
  std::string &pending = stdout_pending();
  if (!pending.empty()) {
    write_stdout_unlocked(pending + "\n");
    pending.clear();
  }
}

void render_progress_frame(std::string_view frame) {
  std::lock_guard lock(console_mutex());
  std::cout << '\r' << frame << std::flush;
}
