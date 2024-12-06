#include "vault.hpp"

#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <ostream>
#include <stdexcept>

#include "sqlite/sqlite_orm.h"
#include "src/base64.hpp"
#include "src/util.hpp"
namespace fs = std::filesystem;

Vault::Vault(const std::string& vault_dir)
    : m_vault_dir(vault_dir),
      m_module(),
      m_storage(initStorage((fs::path(vault_dir) / "keys.db").string()))
{
  m_storage.sync_schema();
}

void Vault::login(const std::string& password)
{
  fs::path dir(m_vault_dir);
  std::string nssPath = (dir / fs::path("nss")).string();
  m_module.login(nssPath, password);
}

void Vault::logout() { m_module.logout(); }

void Vault::create_master_key(const std::string& name)
{
  if (!m_module.createKey(name, KeyType::AES, 256)) {
    throw new std::runtime_error("Could not create master key");
  }

  MasterKey masterKey{MASTER_KEY_ID, name, "AES", 256};
  m_storage.insert(masterKey);
}

void Vault::save_secret(const std::string& name, const std::string& value)
{
  auto masterKey = m_storage.get_pointer<MasterKey>(MASTER_KEY_ID);
  if (!masterKey) {
    throw new std::runtime_error("Could not find master key in db");
  }

  auto key = m_module.findKey(masterKey->alias);
  if (!key.has_value()) {
    throw new std::runtime_error("Could not retreive master key");
  }

  auto iv = m_module.generateRandomBytes(16);
  auto encrypted =
      m_module.encrypt(key.value(), (char*)value.c_str(), value.length(), iv);
  if (!encrypted.has_value()) {
    throw new std::runtime_error("Could not encrypt secret");
  }

  Secret secret = {-1, name, *encrypted, base64_encode(iv.data(), 16)};
  m_storage.insert(secret);
}

void Vault::update_secret(const std::string& name, const std::string& value)
{
  auto secrets = m_storage.get_all<Secret>(where(c(&Secret::name) == name));
  if (secrets.size() == 0) {
    throw new std::runtime_error("Could not find secret");
  }

  auto masterKeyDb = m_storage.get_pointer<MasterKey>(MASTER_KEY_ID);
  if (!masterKeyDb) {
    throw new std::runtime_error("Could not find master key in db");
  }

  auto masterKey = m_module.findKey(masterKeyDb->alias);
  if (!masterKey.has_value()) {
    throw new std::runtime_error("Could not find master key in keystore");
  }

  auto iv = m_module.generateRandomBytes(16);
  auto encrypted = m_module.encrypt(masterKey.value(), (char*)value.c_str(),
                                    value.length(), iv);
  if (!encrypted.has_value()) {
    throw new std::runtime_error("Could not encrypt secret");
  }

  Secret newSecret = {secrets[0].id, name, *encrypted,
                      base64_encode(iv.data(), 16)};
  m_storage.update(newSecret);
}

std::string Vault::get_secret(const std::string& name)
{
  auto secrets = m_storage.get_all<Secret>(where(c(&Secret::name) == name));
  if (secrets.size() == 0) {
    throw new std::runtime_error("Could not find secret");
  }

  auto masterKeyDb = m_storage.get_pointer<MasterKey>(MASTER_KEY_ID);
  if (!masterKeyDb) {
    throw new std::runtime_error("Could not find master key in db");
  }

  auto masterKey = m_module.findKey(masterKeyDb->alias);
  if (!masterKey.has_value()) {
    throw new std::runtime_error("Could not find master key in keystore");
  }

  auto secret = secrets[0];
  auto iv = base64_decode(secret.iv);
  auto decrypted = m_module.decrypt(*masterKey, secret.encryptedText, iv);

  if (!decrypted.has_value()) {
    throw new std::runtime_error("Could not decrypt secret");
  }

  return *decrypted;
}

void Vault::remove_secret(const std::string& name)
{
  auto secrets = m_storage.get_all<Secret>(where(c(&Secret::name) == name));
  if (secrets.size() == 0) {
    throw std::runtime_error("Could not find secret");
  }

  m_storage.remove<Secret>(secrets[0].id);
}

std::string Vault::setup_as_new(const std::string& name,
                                const std::string& password)
{
  std::string cwd = fs::current_path().string();
  std::string pwdf = (fs::path(cwd) / "pwdf").string();

  std::ofstream ofs(pwdf);
  ofs << password;
  ofs.flush();

  std::string path = (fs::current_path() / name).string();
  util::shell_command(std::format("mkdir -p {}", path));
  std::string keysDb = (fs::path(path) / "keys.db").string();
  util::shell_command(std::format("touch {}", keysDb));
  std::string nssDb = (fs::path(path) / "nss").string();
  util::shell_command(std::format("mkdir -p {}", nssDb));
  util::shell_command(std::format("certutil -N -d {} -f {}", nssDb, pwdf));
  fs::remove(pwdf);

  Vault vault(path);
  vault.login(password);
  vault.create_master_key("__pwd_master_0");

  return path;
}

void Vault::rotate_secrets()
{
  auto oldMasterKeyDb = m_storage.get_pointer<MasterKey>(MASTER_KEY_ID);
  if (!oldMasterKeyDb) {
    throw std::runtime_error("Could not find master key in database");
  }

  auto oldMasterKey = m_module.findKey(oldMasterKeyDb->alias);
  if (!oldMasterKey.has_value()) {
    throw std::runtime_error("Could not find master key in keystore");
  }

  std::string newName = util::increment_master_alias(oldMasterKeyDb->alias);
  m_module.createKey(newName, KeyType::AES, 256);
  auto newMasterKey = m_module.findKey(newName);

  auto secrets = m_storage.get_all<Secret>();
  for (const auto& secret : secrets) {
    auto iv = base64_decode(secret.iv);
    auto decrypted = m_module.decrypt(*oldMasterKey, secret.encryptedText, iv);
    auto encrypted = m_module.encrypt(
        *newMasterKey, (char*)(*decrypted).c_str(), (*decrypted).length(), iv);

    Secret newSecret = {secret.id, secret.name, *encrypted,
                        base64_encode(iv.data(), 16)};
    m_storage.update<Secret>(newSecret);
  }

  m_module.deleteKey(*oldMasterKey);
  MasterKey newMasterKeyDb = {MASTER_KEY_ID, newName, "AES", 256};
  m_storage.update<MasterKey>(newMasterKeyDb);
}

void Vault::import_certificate(const std::string& name, const std::string& pem)
{
  m_module.importCertificate(name, pem);
}

std::vector<Secret> Vault::list_secrets()
{
  return m_storage.get_all<Secret>();
}
