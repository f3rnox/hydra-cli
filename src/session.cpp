#include "./session.hpp"

#include <cstddef>
#include <exception>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

constexpr const char *k_session_format_version = "1";

std::string bitmap_to_string(const std::vector<char> &bitmap) {
  std::string out;
  out.reserve(bitmap.size());
  for (const char bit : bitmap) {
    out.push_back(bit != 0 ? '1' : '0');
  }
  return out;
}

void bitmap_from_string(const std::string &value, std::vector<char> &bitmap,
                        std::size_t expected_size) {
  bitmap.assign(expected_size, 0);
  const std::size_t copy_count =
      value.size() < expected_size ? value.size() : expected_size;
  for (std::size_t index = 0; index < copy_count; ++index) {
    bitmap[index] = value[index] == '1' ? 1 : 0;
  }
}

std::string trim_trailing_cr(const std::string &line) {
  if (!line.empty() && line.back() == '\r') {
    return line.substr(0, line.size() - 1);
  }
  return line;
}

bool parse_size_t(const std::string &value, std::size_t &out) {
  if (value.empty()) {
    return false;
  }
  try {
    out = static_cast<std::size_t>(std::stoull(value));
  } catch (const std::invalid_argument &) {
    return false;
  } catch (const std::out_of_range &) {
    return false;
  }
  return true;
}

bool atomic_write_file(const std::filesystem::path &target_path,
                       const std::string &contents) {
  const std::filesystem::path tmp_path = target_path.string() + ".tmp";
  {
    std::ofstream tmp_file(tmp_path, std::ios::out | std::ios::trunc);
    if (!tmp_file.is_open()) {
      return false;
    }
    tmp_file << contents;
    if (!tmp_file.good()) {
      return false;
    }
    tmp_file.flush();
  }

  std::error_code ec;
  std::filesystem::rename(tmp_path, target_path, ec);
  if (ec) {
    std::filesystem::remove(target_path, ec);
    ec.clear();
    std::filesystem::rename(tmp_path, target_path, ec);
  }
  if (ec) {
    std::error_code remove_ec;
    std::filesystem::remove(tmp_path, remove_ec);
    return false;
  }
  return true;
}

} // namespace

Session::Session() = default;

bool Session::is_open() const { return is_open_; }

const std::filesystem::path &Session::file_path() const { return file_path_; }

void Session::reset_state_locked(std::size_t target_count) {
  phase_ = "connect";
  connect_total_ = target_count;
  connect_bitmap_.assign(target_count, 0);
  connected_hosts_.clear();
  auth_target_count_ = 0;
  auth_credential_count_ = 0;
  auth_bitmap_.clear();
  auth_success_ = false;
  auth_host_.clear();
  auth_username_.clear();
  auth_password_.clear();
}

bool Session::open(const std::filesystem::path &session_file_path,
                   std::string_view session_key, std::size_t target_count) {
  std::scoped_lock lock(mutex_);
  file_path_ = session_file_path;
  session_key_ = session_key;
  reset_state_locked(target_count);

  if (std::filesystem::exists(file_path_)) {
    if (!load_from_file_locked()) {
      reset_state_locked(target_count);
    }
    if (connect_bitmap_.size() != target_count) {
      reset_state_locked(target_count);
    }
  }

  is_open_ = save_locked();
  return is_open_;
}

bool Session::load_from_file_locked() {
  std::ifstream input(file_path_);
  if (!input.is_open()) {
    return false;
  }

  std::string saved_version;
  std::string saved_key;
  std::string saved_phase;
  std::size_t saved_connect_total = 0;
  std::string saved_connect_bitmap;
  std::vector<std::string> saved_connected_hosts;
  std::size_t saved_auth_target_count = 0;
  std::size_t saved_auth_credential_count = 0;
  std::string saved_auth_bitmap;
  bool saved_auth_success = false;
  std::string saved_auth_host;
  std::string saved_auth_username;
  std::string saved_auth_password;

  std::string raw_line;
  while (std::getline(input, raw_line)) {
    const std::string line = trim_trailing_cr(raw_line);
    const std::size_t equals_pos = line.find('=');
    if (equals_pos == std::string::npos) {
      continue;
    }
    const std::string key = line.substr(0, equals_pos);
    const std::string value = line.substr(equals_pos + 1);

    if (key == "version") {
      saved_version = value;
    } else if (key == "session_key") {
      saved_key = value;
    } else if (key == "phase") {
      saved_phase = value;
    } else if (key == "connect_total") {
      parse_size_t(value, saved_connect_total);
    } else if (key == "connect_bitmap") {
      saved_connect_bitmap = value;
    } else if (key == "connected_host") {
      saved_connected_hosts.push_back(value);
    } else if (key == "auth_target_count") {
      parse_size_t(value, saved_auth_target_count);
    } else if (key == "auth_credential_count") {
      parse_size_t(value, saved_auth_credential_count);
    } else if (key == "auth_bitmap") {
      saved_auth_bitmap = value;
    } else if (key == "auth_success") {
      saved_auth_success = value == "true";
    } else if (key == "auth_host") {
      saved_auth_host = value;
    } else if (key == "auth_username") {
      saved_auth_username = value;
    } else if (key == "auth_password") {
      saved_auth_password = value;
    }
  }

  if (saved_version != k_session_format_version) {
    return false;
  }
  if (saved_key != session_key_) {
    return false;
  }

  phase_ = saved_phase.empty() ? std::string("connect") : saved_phase;
  connect_total_ = saved_connect_total;
  bitmap_from_string(saved_connect_bitmap, connect_bitmap_,
                     saved_connect_total);
  connected_hosts_ = std::move(saved_connected_hosts);
  auth_target_count_ = saved_auth_target_count;
  auth_credential_count_ = saved_auth_credential_count;
  bitmap_from_string(saved_auth_bitmap, auth_bitmap_,
                     saved_auth_target_count * saved_auth_credential_count);
  auth_success_ = saved_auth_success;
  auth_host_ = std::move(saved_auth_host);
  auth_username_ = std::move(saved_auth_username);
  auth_password_ = std::move(saved_auth_password);
  return true;
}

bool Session::save_locked() const {
  std::ostringstream out;
  out << "version=" << k_session_format_version << '\n';
  out << "session_key=" << session_key_ << '\n';
  out << "phase=" << phase_ << '\n';
  out << "connect_total=" << connect_total_ << '\n';
  out << "connect_bitmap=" << bitmap_to_string(connect_bitmap_) << '\n';
  for (const std::string &host : connected_hosts_) {
    out << "connected_host=" << host << '\n';
  }
  out << "auth_target_count=" << auth_target_count_ << '\n';
  out << "auth_credential_count=" << auth_credential_count_ << '\n';
  out << "auth_bitmap=" << bitmap_to_string(auth_bitmap_) << '\n';
  out << "auth_success=" << (auth_success_ ? "true" : "false") << '\n';
  out << "auth_host=" << auth_host_ << '\n';
  out << "auth_username=" << auth_username_ << '\n';
  out << "auth_password=" << auth_password_ << '\n';
  return atomic_write_file(file_path_, out.str());
}

std::size_t Session::connect_pending_count() const {
  std::scoped_lock lock(mutex_);
  std::size_t pending = 0;
  for (const char bit : connect_bitmap_) {
    if (bit == 0) {
      ++pending;
    }
  }
  return pending;
}

bool Session::connect_should_skip(std::size_t target_index) const {
  std::scoped_lock lock(mutex_);
  if (target_index >= connect_bitmap_.size()) {
    return true;
  }
  return connect_bitmap_[target_index] != 0;
}

bool Session::connect_record(std::size_t target_index, bool connected,
                             const std::string &host) {
  std::scoped_lock lock(mutex_);
  if (target_index >= connect_bitmap_.size()) {
    return false;
  }
  if (connect_bitmap_[target_index] == 0) {
    connect_bitmap_[target_index] = 1;
    if (connected) {
      connected_hosts_.push_back(host);
    }
  }
  return save_locked();
}

std::vector<std::string> Session::connected_hosts() const {
  std::scoped_lock lock(mutex_);
  return connected_hosts_;
}

bool Session::connect_finalize() {
  std::scoped_lock lock(mutex_);
  phase_ = "auth";
  return save_locked();
}

bool Session::auth_init(std::size_t target_count,
                        std::size_t credential_count) {
  std::scoped_lock lock(mutex_);
  if (const std::size_t expected_size = target_count * credential_count;
      auth_target_count_ != target_count ||
      auth_credential_count_ != credential_count ||
      auth_bitmap_.size() != expected_size) {
    auth_target_count_ = target_count;
    auth_credential_count_ = credential_count;
    auth_bitmap_.assign(expected_size, 0);
    auth_success_ = false;
    auth_host_.clear();
    auth_username_.clear();
    auth_password_.clear();
  }
  phase_ = "auth";
  return save_locked();
}

bool Session::auth_should_skip(std::size_t target_index,
                               std::size_t credential_index) const {
  std::scoped_lock lock(mutex_);
  if (auth_credential_count_ == 0) {
    return false;
  }
  const std::size_t flat_index =
      target_index * auth_credential_count_ + credential_index;
  if (flat_index >= auth_bitmap_.size()) {
    return true;
  }
  return auth_bitmap_[flat_index] != 0;
}

bool Session::auth_record(std::size_t target_index,
                          std::size_t credential_index) {
  std::scoped_lock lock(mutex_);
  if (auth_credential_count_ == 0) {
    return false;
  }
  const std::size_t flat_index =
      target_index * auth_credential_count_ + credential_index;
  if (flat_index >= auth_bitmap_.size()) {
    return false;
  }
  auth_bitmap_[flat_index] = 1;
  return save_locked();
}

bool Session::auth_record_success(std::string_view host,
                                  std::string_view username,
                                  std::string_view password) {
  std::scoped_lock lock(mutex_);
  auth_success_ = true;
  auth_host_ = host;
  auth_username_ = username;
  auth_password_ = password;
  phase_ = "done";
  return save_locked();
}

bool Session::auth_succeeded() const {
  std::scoped_lock lock(mutex_);
  return auth_success_;
}

std::string Session::auth_success_host() const {
  std::scoped_lock lock(mutex_);
  return auth_host_;
}

std::string Session::auth_success_username() const {
  std::scoped_lock lock(mutex_);
  return auth_username_;
}

std::string Session::auth_success_password() const {
  std::scoped_lock lock(mutex_);
  return auth_password_;
}

bool Session::mark_done() {
  std::scoped_lock lock(mutex_);
  phase_ = "done";
  return save_locked();
}

void Session::clear() {
  std::scoped_lock lock(mutex_);
  std::error_code ec;
  std::filesystem::remove(file_path_, ec);
  is_open_ = false;
}
