/**
 * @file src/web_sessions.h
 * @brief Bounded browser authentication sessions with optional disk persistence.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>

namespace web_sessions {
  /**
   * @brief Wall-clock used for session expiration and cross-restart persistence.
   */
  using clock = std::chrono::system_clock;

  /**
   * @brief Lifetime for non-persistent browser sessions.
   */
  inline constexpr auto SESSION_TTL = std::chrono::hours(12);

  /**
   * @brief Lifetime for persistent ("remember me") browser sessions.
   */
  inline constexpr auto PERSISTENT_SESSION_TTL = std::chrono::hours(24 * 30);

  /**
   * @brief Minimum interval between sliding-expiration renewals for a persistent session.
   */
  inline constexpr auto SLIDING_RENEWAL_INTERVAL = std::chrono::hours(1);

  /**
   * @brief Maximum number of concurrently tracked browser sessions.
   */
  inline constexpr std::size_t MAX_SESSIONS = 256;

  /**
   * @brief Read the session cookie, rejecting duplicate cookie names.
   * @param cookies Raw Cookie header.
   * @return Opaque token, or an empty string for missing/ambiguous cookies.
   */
  inline std::string cookie_token(std::string_view cookies) {
    std::string result;
    bool found = false;
    while (!cookies.empty()) {
      const auto end = cookies.find(';');
      auto part = cookies.substr(0, end);
      const auto first = part.find_first_not_of(" \t");
      if (first != std::string_view::npos) {
        part.remove_prefix(first);
        part = part.substr(0, part.find_last_not_of(" \t") + 1);
        constexpr std::string_view prefix = "sunshine_session=";
        if (part.starts_with(prefix)) {
          if (found) {
            return {};
          }
          found = true;
          result = part.substr(prefix.size());
        }
      }
      if (end == std::string_view::npos) {
        break;
      }
      cookies.remove_prefix(end + 1);
    }
    return result;
  }

  /**
   * @brief Thread-safe session storage; tokens must come from a cryptographic RNG.
   */
  class store {
  public:
    /**
     * @brief Result of validating a presented browser session token.
     */
    struct validation_result {
      bool ok = false;  ///< Whether the session is active and matches current credentials.
      bool persistent = false;  ///< Whether the session is marked for long-lived persistence.
      bool renewed = false;  ///< Whether sliding renewal extended the expiration deadline.
    };

  private:
    /**
     * @brief Credential snapshot and expiration metadata for a session.
     */
    struct entry {
      std::string credentials;  ///< Credential fingerprint at login time.
      clock::time_point expires;  ///< Absolute wall-clock expiration.
      bool persistent = false;  ///< Whether the session persists across restarts.
      clock::time_point last_renewed;  ///< Wall-clock time of the most recent renewal.
    };

    static constexpr std::string_view FILE_HEADER = "v1";  ///< Serialization format version header.

    std::mutex mutex_;  ///< Serializes session access.
    std::map<std::string, entry, std::less<>> entries_;  ///< Active sessions keyed by random token.
    std::filesystem::path storage_path_;  ///< Optional file path for persistent sessions.

    /**
     * @brief Encode arbitrary bytes as lowercase hexadecimal text.
     * @param input Raw string bytes.
     * @return Hex-encoded representation.
     */
    static std::string hex_encode(std::string_view input) {
      static constexpr char HEX[] = "0123456789abcdef";
      std::string out;
      out.reserve(input.size() * 2);
      for (const unsigned char byte : input) {
        out.push_back(HEX[(byte >> 4) & 0x0F]);
        out.push_back(HEX[byte & 0x0F]);
      }
      return out;
    }

    /**
     * @brief Decode lowercase or uppercase hexadecimal text into raw bytes.
     * @param hex Hex-encoded string.
     * @param out Output string populated on success.
     * @return True when input has valid even-length hex digits.
     */
    static bool hex_decode(std::string_view hex, std::string &out) {
      if (hex.size() % 2 != 0) {
        return false;
      }
      auto nibble = [](const char ch) -> int {
        if (ch >= '0' && ch <= '9') {
          return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
          return 10 + (ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
          return 10 + (ch - 'A');
        }
        return -1;
      };
      out.clear();
      out.reserve(hex.size() / 2);
      for (std::size_t index = 0; index < hex.size(); index += 2) {
        const int hi = nibble(hex[index]);
        const int lo = nibble(hex[index + 1]);
        if (hi < 0 || lo < 0) {
          out.clear();
          return false;
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
      }
      return true;
    }

    /**
     * @brief Check whether a token contains only safe non-whitespace ASCII characters.
     * @param token Candidate session token.
     * @return True when token is non-empty and free of whitespace or delimiters.
     */
    static bool valid_token_chars(std::string_view token) {
      if (token.empty()) {
        return false;
      }
      for (const unsigned char ch : token) {
        if (ch <= 0x20 || ch >= 0x7F || ch == ';') {
          return false;
        }
      }
      return true;
    }

    /**
     * @brief Evict the earliest-expiring entry when storage reaches MAX_SESSIONS.
     */
    void evict_one_locked() {
      if (entries_.empty()) {
        return;
      }
      auto victim = entries_.begin();
      for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->second.expires < victim->second.expires) {
          victim = it;
        }
      }
      entries_.erase(victim);
    }

    /**
     * @brief Persist active long-lived sessions atomically to storage_path_.
     */
    void save_locked() {
      if (storage_path_.empty()) {
        return;
      }

      const auto now = clock::now();
      std::size_t persistent_count = 0;
      for (const auto &[token, item] : entries_) {
        if (item.persistent && item.expires > now) {
          ++persistent_count;
        }
      }

      std::error_code ec;
      if (persistent_count == 0) {
        std::filesystem::remove(storage_path_, ec);
        return;
      }

      if (storage_path_.has_parent_path()) {
        std::filesystem::create_directories(storage_path_.parent_path(), ec);
      }

      auto temp_path = storage_path_;
      temp_path += ".tmp";
      {
        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
          return;
        }
        out << FILE_HEADER << '\n';
        for (const auto &[token, item] : entries_) {
          if (!item.persistent || item.expires <= now || !valid_token_chars(token)) {
            continue;
          }
          const auto expires_sec = std::chrono::duration_cast<std::chrono::seconds>(item.expires.time_since_epoch()).count();
          out << token << ' ' << expires_sec << ' ' << hex_encode(item.credentials) << '\n';
        }
        out.flush();
        if (!out.good()) {
          return;
        }
      }

#ifndef _WIN32
      std::filesystem::permissions(
        temp_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec
      );
#endif
      std::filesystem::rename(temp_path, storage_path_, ec);
      if (ec) {
        std::filesystem::remove(temp_path, ec);
      }
    }

    /**
     * @brief Load persisted sessions from storage_path_, discarding expired or malformed lines.
     */
    void load_locked() {
      if (storage_path_.empty()) {
        return;
      }
      std::ifstream in(storage_path_, std::ios::binary);
      if (!in.is_open()) {
        return;
      }
      std::string header;
      if (!std::getline(in, header)) {
        return;
      }
      if (!header.empty() && header.back() == '\r') {
        header.pop_back();
      }
      if (header != FILE_HEADER) {
        return;
      }

      const auto now = clock::now();
      std::string line;
      while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
          line.pop_back();
        }
        if (line.empty()) {
          continue;
        }
        std::istringstream iss(line);
        std::string token;
        std::int64_t expires_sec = 0;
        std::string creds_hex;
        if (!(iss >> token >> expires_sec >> creds_hex)) {
          continue;
        }
        std::string extra;
        if (iss >> extra) {
          continue;
        }
        if (!valid_token_chars(token)) {
          continue;
        }
        std::string creds;
        if (!hex_decode(creds_hex, creds)) {
          continue;
        }
        const auto expires = clock::time_point(std::chrono::seconds(expires_sec));
        if (expires <= now) {
          continue;
        }
        if (entries_.size() >= MAX_SESSIONS) {
          evict_one_locked();
        }
        entries_[token] = {std::move(creds), expires, true, now};
      }
    }

  public:
    /**
     * @brief Configure the backing file for persistent sessions and load valid entries.
     * @param path File path for storing persistent sessions, or empty to disable disk storage.
     */
    void set_storage_path(const std::filesystem::path &path) {
      std::scoped_lock lock(mutex_);
      storage_path_ = path;
      if (!storage_path_.empty()) {
        load_locked();
      }
    }

    /**
     * @brief Add a session, expiring old entries and bounding memory usage.
     * @param token Fresh random token.
     * @param credentials Current credential fingerprint.
     * @param now Current wall-clock time.
     * @param persistent Whether the session persists for 30 days across restarts.
     */
    void add(const std::string &token, const std::string &credentials, clock::time_point now, bool persistent = false) {
      std::scoped_lock lock(mutex_);
      std::erase_if(entries_, [now](const auto &item) {
        return item.second.expires <= now;
      });
      if (entries_.size() >= MAX_SESSIONS) {
        evict_one_locked();
      }
      const auto ttl = persistent ? std::chrono::duration_cast<clock::duration>(PERSISTENT_SESSION_TTL) : std::chrono::duration_cast<clock::duration>(SESSION_TTL);
      entries_[token] = {credentials, now + ttl, persistent, now};
      if (persistent) {
        save_locked();
      }
    }

    /**
     * @brief Validate a session, apply sliding renewal for persistent sessions, and discard stale entries.
     * @param token Presented cookie token.
     * @param credentials Current credential fingerprint.
     * @param now Current wall-clock time.
     * @return Detailed validation outcome including persistence and renewal flags.
     */
    validation_result check(const std::string &token, const std::string &credentials, clock::time_point now) {
      std::scoped_lock lock(mutex_);
      const auto it = entries_.find(token);
      if (it == entries_.end()) {
        return {};
      }
      if (it->second.expires <= now || it->second.credentials != credentials) {
        const bool was_persistent = it->second.persistent;
        entries_.erase(it);
        if (was_persistent) {
          save_locked();
        }
        return {};
      }
      bool renewed = false;
      if (it->second.persistent && (now >= it->second.last_renewed + SLIDING_RENEWAL_INTERVAL || it->second.expires - now < PERSISTENT_SESSION_TTL / 2)) {
        it->second.expires = now + std::chrono::duration_cast<clock::duration>(PERSISTENT_SESSION_TTL);
        it->second.last_renewed = now;
        renewed = true;
        save_locked();
      }
      return {true, it->second.persistent, renewed};
    }

    /**
     * @brief Check a session and discard expired or credential-stale entries.
     * @param token Presented cookie token.
     * @param credentials Current credential fingerprint.
     * @param now Current wall-clock time.
     * @return Whether the session is active.
     */
    bool valid(const std::string &token, const std::string &credentials, clock::time_point now) {
      return check(token, credentials, now).ok;
    }

    /**
     * @brief Revoke a session.
     * @param token Token to revoke.
     */
    void remove(const std::string &token) {
      std::scoped_lock lock(mutex_);
      const auto it = entries_.find(token);
      if (it == entries_.end()) {
        return;
      }
      const bool was_persistent = it->second.persistent;
      entries_.erase(it);
      if (was_persistent) {
        save_locked();
      }
    }

    /**
     * @brief Revoke all active sessions in memory and optionally remove persisted storage.
     * @param clear_storage When true, also remove any persisted session file on disk.
     */
    void clear(bool clear_storage = true) {
      std::scoped_lock lock(mutex_);
      entries_.clear();
      if (clear_storage && !storage_path_.empty()) {
        std::error_code ec;
        std::filesystem::remove(storage_path_, ec);
      }
    }
  };
}  // namespace web_sessions
