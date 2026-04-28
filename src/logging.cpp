#include "./logging.hpp"

#include <iostream>
#include <mutex>
#include <string>

namespace {

std::mutex g_console_mutex;
std::string g_stdout_pending;

void write_stdout_unlocked(const std::string &text) {
  std::cout << text;
  std::cout.flush();
}

void write_stderr_unlocked(const std::string &text) {
  std::cerr << text;
  std::cerr.flush();
}

} // namespace

void log_info(const std::string &message) {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  write_stdout_unlocked("[info] " + message + "\n");
}

void log_error(const std::string &message) {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  write_stderr_unlocked("[error] " + message + "\n");
}

void log_stdout_line(const std::string &message) {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  write_stdout_unlocked(message + "\n");
}

void log_stderr_line(const std::string &message) {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  write_stderr_unlocked(message + "\n");
}

void log_stdout_chunk(const std::string &chunk) {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  g_stdout_pending.append(chunk);

  size_t newline_position = g_stdout_pending.find('\n');
  while (newline_position != std::string::npos) {
    const std::string complete_line =
        g_stdout_pending.substr(0, newline_position + 1);
    write_stdout_unlocked(complete_line);
    g_stdout_pending.erase(0, newline_position + 1);
    newline_position = g_stdout_pending.find('\n');
  }
}

void flush_stdout_buffer() {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  if (!g_stdout_pending.empty()) {
    write_stdout_unlocked(g_stdout_pending + "\n");
    g_stdout_pending.clear();
  }
}

void render_progress_frame(const std::string &frame) {
  std::lock_guard<std::mutex> lock(g_console_mutex);
  std::cout << '\r' << frame << std::flush;
}
