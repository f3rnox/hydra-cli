#pragma once

#include <string>

void log_info(const std::string &message);
void log_error(const std::string &message);
void log_stdout_line(const std::string &message);
void log_stderr_line(const std::string &message);
void log_stdout_chunk(const std::string &chunk);
void flush_stdout_buffer();
void render_progress_frame(const std::string &frame);
