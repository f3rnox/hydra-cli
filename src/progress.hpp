#pragma once

#include <atomic>
#include <cstddef>
#include <string>
#include <string_view>
#include <thread>

class ProgressIndicator {
public:
  ProgressIndicator();
  ~ProgressIndicator();

  void start(std::size_t total_steps, std::string_view label);
  void increment();
  void stop(std::string_view done_message);

private:
  void run() const;
  void render(char spinner_char) const;
  static std::string build_bar(std::size_t completed_steps,
                               std::size_t total_steps);

  std::atomic<bool> running_;
  std::atomic<std::size_t> completed_steps_;
  std::size_t total_steps_;
  std::string label_;
  std::thread render_thread_;
};
