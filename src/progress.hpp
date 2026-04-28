#pragma once

#include <atomic>
#include <cstddef>
#include <string>
#include <thread>

class ProgressIndicator {
public:
  ProgressIndicator();
  ~ProgressIndicator();

  void start(std::size_t total_steps, const std::string &label);
  void increment();
  void stop(const std::string &done_message);

private:
  void run();
  void render(char spinner_char);
  static std::string build_bar(std::size_t completed_steps,
                               std::size_t total_steps);

  std::atomic<bool> running_;
  std::atomic<std::size_t> completed_steps_;
  std::size_t total_steps_;
  std::string label_;
  std::thread render_thread_;
};
