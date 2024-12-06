#pragma once

#include <cstdint>

#include "key.hpp"
#include "pkcs11/cryptoki.h"
#include "src/base64.hpp"

class Certificate : Key {
  private:
  std::string m_issuer;
  uint64_t m_not_before;
  uint64_t m_not_after;

  public:
  const std::string& issuer() const { return m_issuer; }
  uint64_t notBefore() const { return m_not_before; }
  uint64_t notAfter() const { return m_not_after; }
};

struct DerCert {
  std::vector<BYTE> all;
  std::vector<BYTE> subject;
};
