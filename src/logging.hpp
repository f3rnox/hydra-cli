#pragma once

#include <string>
#include <string_view>

void log_info(std::string_view message);
void log_error(std::string_view message);
void log_stdout_line(std::string_view message);
void log_stderr_line(std::string_view message);
void log_stdout_chunk(std::string_view chunk);
void flush_stdout_buffer();
void render_progress_frame(std::string_view frame);
