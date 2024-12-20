#pragma once

#include <string>

#include "botan/rsa.h"
#include "p11.hpp"
#include "sqlite/sqlite_orm.h"

struct Secret {
  int id;
  std::string name;
  std::string encryptedText;
  std::string iv;
  std::string createdAt;
  std::string updatedAt;
};

struct MasterKey {
  int id;
  std::string alias;
  std::string keyType;
  int bits;
};

using namespace sqlite_orm;

inline auto initStorage(const std::string& path)
{
  auto storage = make_storage(
      path,
      make_table("secret",
                 make_column("id", &Secret::id, primary_key().autoincrement()),
                 make_column("name", &Secret::name),
                 make_column("encrypted_text", &Secret::encryptedText),
                 make_column("iv", &Secret::iv),
                 make_column("created_at", &Secret::createdAt,
                             default_value(current_timestamp())),
                 make_column("updated_at", &Secret::updatedAt,
                             default_value(current_timestamp()))),
      make_table("master_key", make_column("id", &MasterKey::id, primary_key()),
                 make_column("alias", &MasterKey::alias),
                 make_column("key_type", &MasterKey::keyType),
                 make_column("bits", &MasterKey::bits)));
  return storage;
}
using Storage = decltype(initStorage(""));
constexpr const static int MASTER_KEY_ID = 1;

class Vault {
  private:
  std::string m_name;
  std::string m_vault_dir;
  P11Module m_module;
  Storage m_storage;

  public:
  Vault(const std::string& vault_dir, const std::string& name);
  void login(const std::string& password);
  void logout();

  static std::string setup_as_new(const std::string& name,
                                  const std::string& password);
  void create_master_key(const std::string& name);
  void rotate_secrets();
  void import_certificate(const std::string& name, const std::string& pem);
  void import_public_key(const std::string& name,
                         const Botan::RSA_PublicKey& public_key);
  std::vector<Secret> sync_encrypt_secrets_after(const std::string& date_time);

  void create_secret(const std::string& name, const std::string& value);
  void update_secret(const std::string& name, const std::string& value);
  std::string get_secret(const std::string& name);
  void remove_secret(const std::string& name);
  std::vector<Secret> list_secrets();
  void remote_sync(bool local);
};
