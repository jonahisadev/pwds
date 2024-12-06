#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "args/args.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "rang/rang.hpp"
#include "src/base64.hpp"
#include "util.hpp"
#include "vault.hpp"

Vault get_vault(const args::parser& parser)
{
  Config config;
  config.load(util::config_dir() + "/config.toml");

  std::string pass;
  if (!parser.has("pwfile")) {
    pass = util::prompt_password("Enter master password: ");
  }
  else {
    std::ifstream is(parser.get("pwfile"));
    std::string encoded;
    is >> encoded;
    auto decodedBytes = base64_decode(encoded);
    is.close();
    pass = std::string(decodedBytes.begin(), decodedBytes.end());
  }

  Vault vault(config.get_default().location);
  vault.login(pass);

  return vault;
}

void vault_list()
{
  Config config;
  config.load(util::config_dir() + "/config.toml");
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
  config.load(util::config_dir() + "/config.toml");
  config.set_default(name);
}

void vault_create(const std::string& name)
{
  std::cout << "Creating new vault \"" << name << "\"" << std::endl;
  std::string pass1 = util::prompt_password("Enter password: ");
  std::string pass2 = util::prompt_password("Enter same password: ");

  if (pass1 != pass2) {
    std::cerr << "Passwords do not match" << std::endl;
    return;
  }

  auto path = Vault::setup_as_new(name, pass2);
  Config config;
  config.load(util::config_dir() + "/config.toml");

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
  auto pass = util::prompt_password("Enter master password: ");
  auto encoded = base64_encode((unsigned char*)pass.c_str(), pass.length());

  std::ofstream os(parser.get("pwfile"));
  os << encoded;
  os.flush();
  os.close();
}

void vault_sync(const args::parser& parser)
{
  std::ifstream cert("cert.pem");
  std::stringstream ss;
  ss << cert.rdbuf();

  auto vault = get_vault(parser);
  vault.import_certificate("test-cert", ss.str());
}

void secret_create(const args::parser& parser)
{
  auto vault = get_vault(parser);
  std::string value = util::prompt_password("Secret value: ");
  vault.save_secret(parser.get("name"), value);
}

void secret_list()
{
  Config config;
  config.load(util::config_dir() + "/config.toml");

  Vault vault(config.get_default().location);

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
  std::string value = util::prompt_password("Secret value: ");
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
  auto parser = pwd::create_parser();

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

  return 0;
}
