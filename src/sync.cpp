#include "sync.hpp"

#include <curl/curl.h>
#include <curl/easy.h>

#include <cstddef>
#include <cstdint>
#include <format>
#include <iostream>
#include <sstream>

#include "json/json.hpp"

namespace pwds {

using namespace nlohmann;

void from_json(const json& j, GetSyncResponse& res)
{
  j.at("lastSync").get_to(res.last_sync);

  GetSyncResponseTrust trust;
  auto json_trust = j.at("trust");
  json_trust.at("pem").get_to(trust.pem);
  json_trust.at("chain").get_to(trust.chain);

  res.trust = trust;
}

void to_json(json& j, const PostSyncRequestItem& item)
{
  j = json{{"name", item.name}, {"encrypted", item.encrypted_text}};
}

std::size_t http_response(void* buffer, std::size_t size, std::size_t n,
                          void* stream)
{
  std::string data((const char*)buffer, (std::size_t)size * n);
  *((std::stringstream*)stream) << data;
  return size * n;
}

std::optional<GetSyncResponse> get_sync_details(const std::string& base_url)
{
  auto url = std::format("{}/v1/sync", base_url);
  std::stringstream ss;

  auto c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, http_response);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ss);

  auto res = curl_easy_perform(c);
  curl_easy_cleanup(c);

  if (res != CURLE_OK) {
    std::cerr << "Could not perform GET /sync => " << res << std::endl;
    return {};
  }

  auto j = json::parse(ss.str());
  auto response = j.template get<GetSyncResponse>();
  return response;
}

void post_sync_details(const std::string& base_url,
                       const std::vector<PostSyncRequestItem>& items)
{
  auto url = std::format("{}/v1/sync", base_url);
  std::stringstream ss;

  auto payload = json{{"secrets", items}}.dump();

  auto c = curl_easy_init();

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");

  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, http_response);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &ss);
  curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload.c_str());
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);

  auto res = curl_easy_perform(c);
  curl_slist_free_all(headers);
  if (res != CURLE_OK) {
    std::cerr << "Could not perform POST /sync => " << res << std::endl;
    curl_easy_cleanup(c);
    return;
  }

  auto j = json::parse(ss.str());
  bool ok = j["ok"];

  if (!ok) {
    uint32_t http_code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
    std::cerr << "Some server error occurred (" << http_code << ")"
              << std::endl;
  }

  curl_easy_cleanup(c);
}

}  // namespace pwds
