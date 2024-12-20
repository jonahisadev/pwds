#pragma once

#include <optional>
#include <string>
#include <vector>

#include "botan/rsa.h"
#include "key.hpp"
#include "pkcs11/cryptoki.h"

struct Slot {
  CK_SLOT_ID id;
  CK_SLOT_INFO_PTR info;
};

class P11Module {
  private:
  CK_FUNCTION_LIST_PTR m_p11;
  CK_SESSION_HANDLE m_session;

  public:
  P11Module();
  void login(const std::string& nss_path, const std::string& pin);
  void logout();

  bool create_key(const std::string& name, KeyType type, std::size_t bits);
  std::optional<Key> find_key(const std::string& name);
  void delete_key(const std::string& name);
  void delete_key(const Key& key);
  void import_certificate(const std::string& name, const std::string& pem);
  void import_rsa_public_key(const std::string& name,
                             const Botan::RSA_PublicKey& public_key);

  std::optional<std::string> encrypt(const Key& key, char* data,
                                     std::size_t data_len,
                                     std::vector<CK_BYTE> iv);
  std::optional<std::string> decrypt(const Key& key, std::string data,
                                     std::vector<CK_BYTE> iv);

  std::vector<CK_BYTE> generate_random_bytes(std::size_t size);

  private:
  std::vector<Slot> load_slots();
  std::vector<Slot> login(const std::string& nss_path);
  void create_session(CK_SLOT_ID slot_id);
  bool generate_symmetric_key(const std::string& name, KeyType type,
                              std::size_t bits);
};
