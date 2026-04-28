#include "./progress.hpp"

#include "./logging.hpp"

#include <algorithm>
#include <chrono>

namespace {

constexpr std::size_t k_bar_width = 30;
constexpr auto k_frame_delay = std::chrono::milliseconds(80);
constexpr char k_spinner_frames[] = {'|', '/', '-', '\\'};

} // namespace

ProgressIndicator::ProgressIndicator()
    : running_(false), completed_steps_(0), total_steps_(0) {}

ProgressIndicator::~ProgressIndicator() { stop(""); }

void ProgressIndicator::start(std::size_t total_steps,
                              const std::string &label) {
  if (running_.load()) {
    return;
  }

  total_steps_ = std::max<std::size_t>(total_steps, 1);
  label_ = label;
  completed_steps_.store(0);
  running_.store(true);
  render_thread_ = std::thread(&ProgressIndicator::run, this);
}

void ProgressIndicator::increment() {
  if (!running_.load()) {
    return;
  }

  const std::size_t current = completed_steps_.load();
  if (current < total_steps_) {
    completed_steps_.fetch_add(1);
  }
}

void ProgressIndicator::stop(const std::string &done_message) {
  if (!running_.load()) {
    return;
  }

  running_.store(false);
  if (render_thread_.joinable()) {
    render_thread_.join();
  }

  completed_steps_.store(total_steps_);
  render(' ');

  if (!done_message.empty()) {
    log_stdout_line(" " + done_message);
    return;
  }
  log_stdout_line("");
}

void ProgressIndicator::run() {
  std::size_t frame_index = 0;
  while (running_.load()) {
    render(k_spinner_frames[frame_index % (sizeof(k_spinner_frames) /
                                           sizeof(k_spinner_frames[0]))]);
    ++frame_index;
    std::this_thread::sleep_for(k_frame_delay);
  }
}

void ProgressIndicator::render(char spinner_char) {
  const std::size_t completed_steps =
      std::min(completed_steps_.load(), total_steps_);
  const std::string bar = build_bar(completed_steps, total_steps_);
  const std::size_t percent = (completed_steps * 100) / total_steps_;

  render_progress_frame(std::string(1, spinner_char) + " " + label_ + " " +
                        bar + " " + std::to_string(completed_steps) + "/" +
                        std::to_string(total_steps_) + " (" +
                        std::to_string(percent) + "%)");
}

std::string ProgressIndicator::build_bar(std::size_t completed_steps,
                                         std::size_t total_steps) {
  const std::size_t filled = (completed_steps * k_bar_width) / total_steps;

  std::string bar = "[";
  bar.reserve(k_bar_width + 2);
  for (std::size_t i = 0; i < k_bar_width; ++i) {
    bar.push_back(i < filled ? '#' : '-');
  }
  bar.push_back(']');
  return bar;
}
