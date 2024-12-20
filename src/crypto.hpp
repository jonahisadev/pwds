#pragma once

#include <botan/rsa.h>
#include <botan/x509cert.h>

namespace pwds {
namespace crypto {

Botan::X509_Certificate load_cert_pem(const std::string& path);
Botan::RSA_PublicKey extract_pubk_from_cert(
    const Botan::X509_Certificate& cert);
bool validate_cert(const Botan::X509_Certificate& cert,
                   std::vector<Botan::X509_Certificate> bundle);

}  // namespace crypto
}  // namespace pwds
