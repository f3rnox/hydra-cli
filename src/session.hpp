#pragma once

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

class Session {
public:
  Session();

  bool open(const std::filesystem::path &session_file_path,
            const std::string &session_key, std::size_t target_count);

  bool is_open() const;
  const std::filesystem::path &file_path() const;

  std::size_t connect_pending_count() const;
  bool connect_should_skip(std::size_t target_index) const;
  bool connect_record(std::size_t target_index, bool connected,
                      const std::string &host);
  std::vector<std::string> connected_hosts() const;
  bool connect_finalize();

  bool auth_init(std::size_t target_count, std::size_t credential_count);
  bool auth_should_skip(std::size_t target_index,
                        std::size_t credential_index) const;
  bool auth_record(std::size_t target_index, std::size_t credential_index);
  bool auth_record_success(const std::string &host, const std::string &username,
                           const std::string &password);
  bool auth_succeeded() const;
  std::string auth_success_host() const;
  std::string auth_success_username() const;
  std::string auth_success_password() const;

  bool mark_done();
  void clear();

private:
  bool save_locked() const;
  bool load_from_file_locked();
  void reset_state_locked(std::size_t target_count);

  mutable std::mutex mutex_;
  std::filesystem::path file_path_;
  std::string session_key_;
  bool is_open_ = false;

  std::string phase_;
  std::size_t connect_total_ = 0;
  std::vector<char> connect_bitmap_;
  std::vector<std::string> connected_hosts_;

  std::size_t auth_target_count_ = 0;
  std::size_t auth_credential_count_ = 0;
  std::vector<char> auth_bitmap_;
  bool auth_success_ = false;
  std::string auth_host_;
  std::string auth_username_;
  std::string auth_password_;
};
