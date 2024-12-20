#include "vault.hpp"

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "base64/base64.hpp"
#include "sqlite/sqlite_orm.h"
#include "src/config.hpp"
#include "src/crypto.hpp"
#include "src/sync.hpp"
#include "src/util.hpp"

namespace fs = std::filesystem;

Vault::Vault(const std::string& vault_dir, const std::string& name)
    : m_name(name),
      m_vault_dir(vault_dir),
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
  if (!m_module.create_key(name, KeyType::AES, 256)) {
    throw new std::runtime_error("Could not create master key");
  }

  MasterKey masterKey{MASTER_KEY_ID, name, "AES", 256};
  m_storage.insert(masterKey);
}

void Vault::create_secret(const std::string& name, const std::string& value)
{
  auto masterKey = m_storage.get_pointer<MasterKey>(MASTER_KEY_ID);
  if (!masterKey) {
    throw new std::runtime_error("Could not find master key in db");
  }

  auto key = m_module.find_key(masterKey->alias);
  if (!key.has_value()) {
    throw new std::runtime_error("Could not retreive master key");
  }

  auto iv = m_module.generate_random_bytes(16);
  auto encrypted =
      m_module.encrypt(key.value(), (char*)value.c_str(), value.length(), iv);
  if (!encrypted.has_value()) {
    throw new std::runtime_error("Could not encrypt secret");
  }

  Secret secret = {
      -1,
      name,
      *encrypted,
      base64::encode_into<std::string>(iv.data(), iv.data() + iv.size()),
      pwds::util::current_time(),
      pwds::util::current_time()};
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

  auto masterKey = m_module.find_key(masterKeyDb->alias);
  if (!masterKey.has_value()) {
    throw new std::runtime_error("Could not find master key in keystore");
  }

  auto iv = m_module.generate_random_bytes(16);
  auto encrypted = m_module.encrypt(masterKey.value(), (char*)value.c_str(),
                                    value.length(), iv);
  if (!encrypted.has_value()) {
    throw new std::runtime_error("Could not encrypt secret");
  }

  Secret newSecret = {
      secrets[0].id,
      name,
      *encrypted,
      base64::encode_into<std::string>(iv.data(), iv.data() + iv.size()),
      secrets[0].createdAt,
      pwds::util::current_time()};
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

  auto masterKey = m_module.find_key(masterKeyDb->alias);
  if (!masterKey.has_value()) {
    throw new std::runtime_error("Could not find master key in keystore");
  }

  auto secret = secrets[0];
  auto iv = base64::decode_into<std::vector<uint8_t>>(secret.iv);
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
  pwds::util::shell_command(std::format("mkdir -p {}", path));
  std::string keysDb = (fs::path(path) / "keys.db").string();
  pwds::util::shell_command(std::format("touch {}", keysDb));
  std::string nssDb = (fs::path(path) / "nss").string();
  pwds::util::shell_command(std::format("mkdir -p {}", nssDb));
  pwds::util::shell_command(
      std::format("certutil -N -d {} -f {}", nssDb, pwdf));
  fs::remove(pwdf);

  Vault vault(path, name);
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

  auto oldMasterKey = m_module.find_key(oldMasterKeyDb->alias);
  if (!oldMasterKey.has_value()) {
    throw std::runtime_error("Could not find master key in keystore");
  }

  std::string newName =
      pwds::util::increment_master_alias(oldMasterKeyDb->alias);
  m_module.create_key(newName, KeyType::AES, 256);
  auto newMasterKey = m_module.find_key(newName);

  auto secrets = m_storage.get_all<Secret>();
  for (const auto& secret : secrets) {
    auto iv = base64::decode_into<std::vector<uint8_t>>(secret.iv);
    auto decrypted = m_module.decrypt(*oldMasterKey, secret.encryptedText, iv);
    auto encrypted = m_module.encrypt(
        *newMasterKey, (char*)(*decrypted).c_str(), (*decrypted).length(), iv);

    Secret newSecret = {
        secret.id, secret.name, *encrypted,
        base64::encode_into<std::string>(iv.data(), iv.data() + iv.size())};
    m_storage.update<Secret>(newSecret);
  }

  m_module.delete_key(*oldMasterKey);
  MasterKey newMasterKeyDb = {MASTER_KEY_ID, newName, "AES", 256};
  m_storage.update<MasterKey>(newMasterKeyDb);
}

void Vault::import_certificate(const std::string& name,
                               const std::string& pemPath)
{
  m_module.import_certificate(name, pemPath);
}

void Vault::import_public_key(const std::string& name,
                              const Botan::RSA_PublicKey& public_key)
{
  m_module.import_rsa_public_key(name, public_key);
}

std::vector<Secret> Vault::sync_encrypt_secrets_after(
    const std::string& date_time)
{
  auto secrets =
      m_storage.get_all<Secret>(where(c(&Secret::updatedAt) > date_time));
  if (secrets.size() == 0) {
    return {};
  }

  auto masterKeyDb = m_storage.get_pointer<MasterKey>(MASTER_KEY_ID);
  if (!masterKeyDb) {
    throw std::runtime_error("Could not find master key in db");
  }

  auto masterKey = m_module.find_key(masterKeyDb->alias);
  if (!masterKey.has_value()) {
    throw std::runtime_error("Could not find master key in keystore");
  }

  auto syncKey = m_module.find_key("sync-encryption-key");
  if (!syncKey.has_value()) {
    throw std::runtime_error("Could not find sync encryption key");
  }

  for (auto& s : secrets) {
    auto iv = base64::decode_into<std::vector<uint8_t>>(s.iv);
    auto decrypted = m_module.decrypt(*masterKey, s.encryptedText, iv);

    auto encrypted = m_module.encrypt(*syncKey, (char*)(*decrypted).c_str(),
                                      (*decrypted).length(), {});
    if (!encrypted.has_value()) {
      throw std::runtime_error(
          "Could not encrypt data with sync encryption key");
    }

    s.encryptedText = *encrypted;
    s.iv = "";
  }

  return secrets;
}

void Vault::remote_sync(bool local)
{
  // 0. Get server URL
  std::string url;
  if (local) {
    url = "http://localhost:3000";
  }
  else {
    Config config;
    config.load(pwds::util::config_dir() + "/config.toml");
    auto vault_config = config.get_by_name(m_name);
    url = vault_config->syncUrl;
  }

  // 1. Get sync details from server
  auto sync_details = pwds::get_sync_details(url);
  if (!sync_details.has_value()) {
    std::cerr << "Did not receive any value from HTTP request" << std::endl;
    return;
  }
  std::cout << "Received trust from remote server." << std::endl;

  auto cert = pwds::crypto::load_cert_pem(sync_details->trust.pem);
  std::vector<decltype(cert)> bundle = {};
  for (const auto& b : sync_details->trust.chain) {
    bundle.push_back(pwds::crypto::load_cert_pem(b));
  }

  // 2. Validate certificate
  bool validationResult = pwds::crypto::validate_cert(cert, bundle);
  if (!validationResult) {
    std::cout << "WARNING: Certificate is not signed by a trusted CA"
              << std::endl;
    auto confirm = pwds::util::prompt("Continue? [y/N]: ");
    if (std::tolower(confirm[0]) != 'y') {
      return;
    }
  }

  // 3. Import public key from certificate
  auto pubKey = pwds::crypto::extract_pubk_from_cert(cert);
  import_public_key("sync-encryption-key", pubKey);

  // 4. Encrypt keys updated after given time
  auto encrypted = sync_encrypt_secrets_after(sync_details->last_sync);
  auto items = std::vector<pwds::PostSyncRequestItem>();
  for (const auto& s : encrypted) {
    items.push_back({s.name, s.encryptedText});
  }
  pwds::post_sync_details(url, items);
  std::cout << "Synced with remote server." << std::endl;
}

std::vector<Secret> Vault::list_secrets()
{
  return m_storage.get_all<Secret>();
}
