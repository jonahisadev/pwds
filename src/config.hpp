#pragma once

#include <string>
#include <unordered_map>
#include <vector>

// === Config Example ===
//
// [vault]
// default = "main"
//
// [vaults.main]
// location = "/some/path"
//
// [vaults.second]
// location = "/some/other/path"

struct VaultConfig {
  std::string name;
  std::string location;
};

class Config {
  private:
  bool m_loaded;
  std::string m_default;
  std::unordered_map<std::string, VaultConfig> m_vaults;
  inline bool is_loaded() const { return m_loaded; }
  bool has_vault(const std::string& name);
  bool write_config();

  public:
  Config();
  bool load(const std::string& path);
  const VaultConfig& get_default();
  std::vector<VaultConfig> get_all();
  void add_vault(const VaultConfig& config);
  bool set_default(const std::string& name);
};
