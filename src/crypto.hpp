#pragma once

#include "src/cert.hpp"
#include "src/key.hpp"

namespace crypto {

DerCert cert_der_from_pem(const std::string& pem);
PublicKeyRSA extract_pub_from_cert(const DerCert& cert);

}  // namespace crypto
