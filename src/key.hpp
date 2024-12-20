#pragma once

#include <string>

#include "pkcs11/cryptoki.h"

enum KeyType { AES, RSA };

class Key {
  private:
  CK_OBJECT_HANDLE m_handle;
  KeyType m_type;
  std::string m_alias;
  bool m_decrypt;
  bool m_encrypt;

  public:
  Key(CK_OBJECT_HANDLE handle, KeyType type, const std::string& alias);
  inline bool canDecrypt() const { return m_decrypt; }
  inline bool canEncrypt() const { return m_encrypt; }
  void setDecrypt(bool decrypt) { m_decrypt = decrypt; }
  void setEncrypt(bool encrypt) { m_encrypt = encrypt; }

  inline CK_OBJECT_HANDLE getHandle() const { return m_handle; }
  const std::string& getAlias() const { return m_alias; }
  inline KeyType getKeyType() const { return m_type; }
};
