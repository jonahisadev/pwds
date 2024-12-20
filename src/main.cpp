#include <fstream>
#include <iostream>
#include <string>

#include "args/args.hpp"
#include "base64/base64.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "rang/rang.hpp"
#include "util.hpp"
#include "vault.hpp"

Vault get_vault(const args::parser& parser)
{
  Config config;
  config.load(pwds::util::config_dir() + "/config.toml");

  std::string pass;
  if (!parser.has("pwfile")) {
    pass = pwds::util::prompt_password("Enter master password: ");
  }
  else {
    std::ifstream is(parser.get("pwfile"));
    std::string encoded;
    is >> encoded;
    is.close();
    pass = base64::from_base64(encoded);
  }

  Vault vault(config.get_default().location, config.get_default().name);
  vault.login(pass);

  return vault;
}

void vault_list()
{
  Config config;
  config.load(pwds::util::config_dir() + "/config.toml");
  auto vaults = config.get_all();
  auto defaultVault = config.get_default();

  std::cout << "NAME\t\t\tLOCATION" << std::endl;
  for (const auto& vault : vaults) {
    if (defaultVault.name == vault.name) {
      using namespace rang;
      std::cout << "*" << style::bold << fg::green << vault.name << style::reset
                << fg::reset;
    }
    else {
      std::cout << vault.name;
    }
    std::cout << "\t\t\t" << vault.location << std::endl;
  }
}

void vault_select(const std::string& name)
{
  Config config;
  config.load(pwds::util::config_dir() + "/config.toml");
  config.set_default(name);
}

void vault_create(const std::string& name)
{
  std::cout << "Creating new vault \"" << name << "\"" << std::endl;
  std::string pass1 = pwds::util::prompt_password("Enter password: ");
  std::string pass2 = pwds::util::prompt_password("Enter same password: ");

  if (pass1 != pass2) {
    std::cerr << "Passwords do not match" << std::endl;
    return;
  }

  auto path = Vault::setup_as_new(name, pass2);
  Config config;
  config.load(pwds::util::config_dir() + "/config.toml");

  VaultConfig vaultConfig{name, path};
  config.add_vault(vaultConfig);
}

void vault_rotate(const args::parser& parser)
{
  auto vault = get_vault(parser);
  vault.rotate_secrets();
}

void vault_persist(const args::parser& parser)
{
  auto pass = pwds::util::prompt_password("Enter master password: ");
  auto encoded = base64::to_base64(pass);

  std::ofstream os(parser.get("pwfile"));
  os << encoded;
  os.flush();
  os.close();
}

void vault_sync(const args::parser& parser)
{
  auto vault = get_vault(parser);
  auto local = parser.get_as<bool>("local");
  vault.remote_sync(local);
}

void secret_create(const args::parser& parser)
{
  auto vault = get_vault(parser);
  std::string value = pwds::util::prompt_password("Secret value: ");
  vault.create_secret(parser.get("name"), value);
}

void secret_list()
{
  Config config;
  config.load(pwds::util::config_dir() + "/config.toml");

  Vault vault(config.get_default().location, config.get_default().name);

  auto allSecrets = vault.list_secrets();

  std::cout << "NAME" << std::endl;
  for (const auto& s : allSecrets) {
    std::cout << s.name << std::endl;
  }
}

void secret_load(const args::parser& parser)
{
  auto vault = get_vault(parser);
  std::string value = vault.get_secret(parser.get("name"));
  std::cout << value;
  std::cout.flush();
}

void secret_set(const args::parser& parser)
{
  auto vault = get_vault(parser);
  std::string value = pwds::util::prompt_password("Secret value: ");
  auto name = parser.get("name");
  vault.update_secret(name, value);

  std::cout << "Updated secret \"" << name << "\"" << std::endl;
}

void secret_delete(const args::parser& parser)
{
  auto vault = get_vault(parser);
  vault.remove_secret(parser.get("name"));
}

int main(int argc, char** argv)
{
  auto parser = pwds::create_parser();

  if (!parser.parse(argc, argv)) {
    return 1;
  }

  auto subs = parser.subs();
  if (subs[0] == "vault") {
    if (subs[1] == "create") {
      vault_create(parser.get("name"));
    }
    else if (subs[1] == "list") {
      vault_list();
    }
    else if (subs[1] == "select") {
      vault_select(parser.get("name"));
    }
    else if (subs[1] == "rotate") {
      vault_rotate(parser);
    }
    else if (subs[1] == "persist") {
      vault_persist(parser);
    }
    else if (subs[1] == "sync") {
      vault_sync(parser);
    }
  }

  else if (subs[0] == "secret") {
    if (subs[1] == "create") {
      secret_create(parser);
    }
    else if (subs[1] == "get") {
      secret_load(parser);
    }
    else if (subs[1] == "list") {
      secret_list();
    }
    else if (subs[1] == "set") {
      secret_set(parser);
    }
    else if (subs[1] == "delete") {
      secret_delete(parser);
    }
  }

  else if (subs[0] == "config") {
    if (subs[1] == "sync-url") {
      Config config;
      config.load(pwds::util::config_dir() + "/config.toml");
      config.get_default().syncUrl = parser.get("value");
      config.write_config();
    }
  }

  return 0;
}
