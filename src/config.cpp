#include "config.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

#include "src/util.hpp"
namespace fs = std::filesystem;

#include "toml++/toml.hpp"

Config::Config() : m_loaded(false), m_default(""), m_vaults({}) {}

bool Config::load(const std::string& path)
{
  if (!fs::exists(path)) {
    std::ofstream output(path);
    m_loaded = true;
    return true;
  }

  toml::table table;
  try {
    table = toml::parse_file(path);
  }
  catch (const toml::parse_error& err) {
    std::cerr << "Failed to parse config file " << err << std::endl;
    return false;
  }

  m_default = table["vault"]["default"].value_or("");

  for (auto&& [k, v] : *table["vaults"].as_table()) {
    auto opts = *v.as_table();

    VaultConfig vaultConfig;
    vaultConfig.name = k;
    vaultConfig.location = opts["location"].value_or("");
    vaultConfig.syncUrl = opts["sync_url"].value_or("");
    m_vaults.insert({vaultConfig.name, vaultConfig});
  }

  m_loaded = true;
  return true;
}

bool Config::has_vault(const std::string& name)
{
  return m_vaults.count(name) > 0;
}

VaultConfig& Config::get_default()
{
  if (!is_loaded()) {
    throw new std::runtime_error("Attempted to get config before load");
  }

  auto& vault = m_vaults[m_default];
  return vault;
}

std::vector<VaultConfig> Config::get_all()
{
  std::vector<VaultConfig> vec;
  for (auto [_, v] : m_vaults) {
    vec.push_back(v);
  }
  return vec;
}

bool Config::set_default(const std::string& name)
{
  if (!has_vault(name)) {
    std::cerr << "No vault named " << name << " found in configuration"
              << std::endl;
    return false;
  }

  m_default = name;
  return write_config();
}

bool Config::write_config()
{
  toml::table vaultsTable;
  for (auto& [k, v] : m_vaults) {
    toml::table vaultTable;
    vaultTable.emplace("location", v.location);
    vaultTable.emplace("sync_url", v.syncUrl);
    vaultsTable.emplace(k, vaultTable);
  }

  auto table = toml::table{{"vault", toml::table{{"default", m_default}}}};
  table.emplace("vaults", vaultsTable);

  std::string tomlPath = fs::path(pwds::util::config_dir()) / "config.toml";
  std::ofstream os(tomlPath);
  os << table;
  return true;
}

void Config::add_vault(const VaultConfig& config)
{
  m_vaults.insert({config.name, config});
  if (m_default.empty()) {
    m_default = config.name;
  }
  write_config();
}

std::optional<VaultConfig> Config::get_by_name(const std::string& name)
{
  if (!is_loaded()) {
    throw std::runtime_error("Attempted to get config before load");
  }

  if (m_vaults.count(name) == 0) {
    return {};
  }

  return m_vaults.at(name);
}
