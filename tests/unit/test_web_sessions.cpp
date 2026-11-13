/**
 * @file tests/unit/test_web_sessions.cpp
 * @brief Test browser session expiry, persistence, sliding renewal, revocation, and cookie parsing.
 */
#include "src/web_sessions.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

TEST(WebSessions, Lifecycle) {
  web_sessions::store sessions;
  const auto now = web_sessions::clock::now();
  sessions.add("token", "credentials", now);
  EXPECT_TRUE(sessions.valid("token", "credentials", now));
  EXPECT_FALSE(sessions.valid("unknown", "credentials", now));
  EXPECT_FALSE(sessions.valid("token", "changed", now));
  sessions.add("token", "credentials", now);
  EXPECT_FALSE(sessions.valid("token", "credentials", now + web_sessions::SESSION_TTL));
  sessions.add("token", "credentials", now);
  sessions.remove("token");
  EXPECT_FALSE(sessions.valid("token", "credentials", now));
  sessions.add("token", "credentials", now);
  sessions.clear();
  EXPECT_FALSE(sessions.valid("token", "credentials", now));
}

TEST(WebSessions, CookieParsing) {
  EXPECT_EQ(web_sessions::cookie_token("other=x; sunshine_session=abc; third=y"), "abc");
  EXPECT_EQ(web_sessions::cookie_token(" sunshine_session=abc "), "abc");
  EXPECT_TRUE(web_sessions::cookie_token("not_sunshine_session=abc").empty());
  EXPECT_TRUE(web_sessions::cookie_token("sunshine_session=").empty());
  EXPECT_TRUE(web_sessions::cookie_token("sunshine_session=a; sunshine_session=b").empty());
  EXPECT_TRUE(web_sessions::cookie_token("").empty());
  EXPECT_TRUE(web_sessions::cookie_token(" ; \t ; other=x").empty());
}

TEST(WebSessions, BoundedStorageAndExpiredEntryCleanup) {
  web_sessions::store sessions;
  const auto now = web_sessions::clock::now();
  sessions.add("old", "credentials", now - web_sessions::SESSION_TTL);
  sessions.add("fresh", "credentials", now);
  EXPECT_FALSE(sessions.valid("old", "credentials", now));
  EXPECT_TRUE(sessions.valid("fresh", "credentials", now));
  for (int i = 0; i < 300; ++i) {
    sessions.add(std::to_string(i), "credentials", now);
  }
  int active = sessions.valid("fresh", "credentials", now) ? 1 : 0;
  for (int i = 0; i < 300; ++i) {
    active += sessions.valid(std::to_string(i), "credentials", now) ? 1 : 0;
  }
  EXPECT_EQ(active, static_cast<int>(web_sessions::MAX_SESSIONS));
}

TEST(WebSessions, PersistenceAndSlidingRenewalAcrossRestarts) {
  const auto session_file = std::filesystem::temp_directory_path() / "sunshine_test_web_sessions.dat";
  std::error_code ec;
  std::filesystem::remove(session_file, ec);

  const auto now = web_sessions::clock::now();
  {
    web_sessions::store sessions;
    sessions.set_storage_path(session_file);
    sessions.add("persist-token", "creds:1", now, true);
    sessions.add("ephemeral-token", "creds:1", now, false);
    sessions.clear(false);
  }

  {
    web_sessions::store reloaded;
    reloaded.set_storage_path(session_file);
    EXPECT_FALSE(reloaded.valid("ephemeral-token", "creds:1", now));

    const auto renewal_time = now + std::chrono::hours(24 * 20);
    const auto result = reloaded.check("persist-token", "creds:1", renewal_time);
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.persistent);
    EXPECT_TRUE(result.renewed);

    const auto throttled = reloaded.check("persist-token", "creds:1", renewal_time + std::chrono::minutes(10));
    EXPECT_TRUE(throttled.ok);
    EXPECT_FALSE(throttled.renewed);

    EXPECT_TRUE(reloaded.valid("persist-token", "creds:1", now + std::chrono::hours(24 * 35)));
    reloaded.remove("persist-token");
  }

  {
    web_sessions::store after_logout;
    after_logout.set_storage_path(session_file);
    EXPECT_FALSE(after_logout.valid("persist-token", "creds:1", now));
  }

  std::filesystem::remove(session_file, ec);
}

TEST(WebSessions, IgnoresCorruptStorageAndClearsOnRevocation) {
  const auto session_file = std::filesystem::temp_directory_path() / "sunshine_test_web_sessions_corrupt.dat";
  std::error_code ec;
  std::filesystem::remove(session_file, ec);

  const auto now = web_sessions::clock::now();
  const auto future_sec = std::chrono::duration_cast<std::chrono::seconds>((now + std::chrono::hours(24)).time_since_epoch()).count();
  const auto past_sec = std::chrono::duration_cast<std::chrono::seconds>((now - std::chrono::hours(1)).time_since_epoch()).count();

  {
    std::ofstream bad_header(session_file, std::ios::binary | std::ios::trunc);
    bad_header << "v999\ntok " << future_sec << " 616263\n";
  }
  {
    web_sessions::store store_bad;
    store_bad.set_storage_path(session_file);
    EXPECT_FALSE(store_bad.valid("tok", "abc", now));
  }

  {
    std::ofstream mixed(session_file, std::ios::binary | std::ios::trunc);
    mixed << "v1\n"
          << "expired " << past_sec << " 616263\n"
          << "badhex " << future_sec << " zzzz\n"
          << "extra " << future_sec << " 616263 trailing\n"
          << "good " << future_sec << " 616263\n";
  }
  {
    web_sessions::store store_mixed;
    store_mixed.set_storage_path(session_file);
    EXPECT_FALSE(store_mixed.valid("expired", "abc", now));
    EXPECT_FALSE(store_mixed.valid("badhex", "abc", now));
    EXPECT_FALSE(store_mixed.valid("extra", "abc", now));
    EXPECT_TRUE(store_mixed.valid("good", "abc", now));

    EXPECT_FALSE(store_mixed.valid("good", "changed", now));
    EXPECT_FALSE(std::filesystem::exists(session_file));

    store_mixed.add("readded", "abc", now, true);
    EXPECT_TRUE(std::filesystem::exists(session_file));
    store_mixed.clear(true);
    EXPECT_FALSE(std::filesystem::exists(session_file));
  }

  std::filesystem::remove(session_file, ec);
}
