#pragma once

#include <optional>
#include <string>
#include <vector>

#include "key.hpp"
#include "pkcs11/cryptoki.h"
#include "src/cert.hpp"

enum KeyType { AES };

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
  void login(const std::string& nssPath, const std::string& pin);
  void logout();

  bool createKey(const std::string& name, KeyType type, std::size_t bits);
  std::optional<Key> findKey(const std::string& name);
  void deleteKey(const std::string& name);
  void deleteKey(const Key& key);
  void importCertificate(const std::string& name, const std::string& pem);

  std::optional<std::string> encrypt(const Key& key, char* data,
                                     std::size_t dataLen,
                                     std::vector<CK_BYTE> iv);
  std::optional<std::string> decrypt(const Key& key, std::string data,
                                     std::vector<CK_BYTE> iv);

  std::vector<CK_BYTE> generateRandomBytes(std::size_t size);

  private:
  std::vector<Slot> load_slots();
  std::vector<Slot> login(const std::string& nssPath);
  void create_session(CK_SLOT_ID slotId);
  bool generateSymmetricKey(const std::string& name, KeyType type,
                            std::size_t bits);
};
