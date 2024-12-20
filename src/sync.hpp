#pragma once

#include <optional>
#include <string>
#include <vector>

namespace pwds {

struct GetSyncResponseTrust {
  std::string pem;
  std::vector<std::string> chain;
};

struct GetSyncResponse {
  std::string last_sync;
  GetSyncResponseTrust trust;
};

struct PostSyncRequestItem {
  std::string name;
  std::string encrypted_text;
};

std::optional<GetSyncResponse> get_sync_details(const std::string& base_url);
void post_sync_details(const std::string& base_url,
                       const std::vector<PostSyncRequestItem>& items);

}  // namespace pwds
