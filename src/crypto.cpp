#include "crypto.hpp"

#include <botan/certstor_system.h>
#include <botan/rsa.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>

#include <cstdint>
#include <iostream>

#include "base64/base64.hpp"
#include "botan/data_src.h"

namespace pwds {

namespace crypto {

Botan::X509_Certificate load_cert_pem(const std::string& pem)
{
  Botan::DataSource_Memory ds(pem.data());
  return Botan::X509_Certificate(ds);
}

Botan::RSA_PublicKey extract_pubk_from_cert(const Botan::X509_Certificate& cert)
{
  auto publicKey = cert.subject_public_key();
  return Botan::RSA_PublicKey(publicKey->algorithm_identifier(),
                              publicKey->public_key_bits());
}

bool validate_cert(const Botan::X509_Certificate& cert,
                   std::vector<Botan::X509_Certificate> chain)
{
  Botan::System_Certificate_Store certStore;
  Botan::Path_Validation_Restrictions restrictions;

  std::vector<Botan::X509_Certificate> end_certs;
  end_certs.push_back(cert);
  for (const auto& c : chain) {
    end_certs.push_back(c);
  }

  auto validationResult =
      Botan::x509_path_validate(end_certs, restrictions, certStore);

  return validationResult.successful_validation();
}

}  // namespace crypto
}  // namespace pwds
