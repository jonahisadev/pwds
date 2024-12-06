#include "crypto.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>

#include "src/key.hpp"

std::string opensslError()
{
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* buf;
  size_t len = BIO_get_mem_data(bio, &buf);
  std::string result(buf, len);
  BIO_free(bio);
  return result;
}

namespace crypto {

DerCert cert_der_from_pem(const std::string& pem)
{
  // Read PEM into X509 object
  X509* cert = NULL;
  BIO* pem_ptr = BIO_new(BIO_s_mem());
  BIO_write(pem_ptr, (void*)pem.c_str(), pem.length());
  cert = PEM_read_bio_X509(pem_ptr, nullptr, nullptr, nullptr);
  if (!cert) {
    std::cerr << opensslError() << std::endl;
    throw std::runtime_error("OpenSSL Error");
  }

  // Get subject
  unsigned char subj[512];
  unsigned char* subjp = subj;
  X509_NAME* name_obj = X509_get_subject_name(cert);
  long name_len = i2d_X509_NAME(name_obj, &subjp);
  if (name_len < 0) {
    std::cerr << opensslError() << std::endl;
    throw std::runtime_error("OpenSSL Error");
  }
  std::vector<BYTE> subj_bytes;
  subj_bytes.assign(subj, subj + name_len);

  // Convert to DER in memory
  BIO* der_ptr = BIO_new(BIO_s_mem());
  i2d_X509_bio(der_ptr, cert);
  BUF_MEM* mem = NULL;
  BIO_get_mem_ptr(der_ptr, &mem);

  // Load into vector
  std::vector<BYTE> bytes;
  bytes.assign(mem->data, mem->data + mem->length);

  // Clean up
  // BIO_free(pem_ptr);
  // BIO_free(der_ptr);
  // X509_free(cert);

  // Done
  return DerCert{bytes, subj_bytes};
}

PublicKeyRSA extract_pub_from_cert(const DerCert& cert)
{
  X509* x509;
  EVP_PKEY* pubkey;
  RSA* rsa;
  PublicKeyRSA obj;

  auto* dataPtr = cert.all.data();

  x509 = d2i_X509(nullptr, &dataPtr, cert.all.size());
  pubkey = X509_get_pubkey(x509);
  rsa = EVP_PKEY_get1_RSA(pubkey);

  unsigned char buffer[2048];
  uint64_t len;

  const BIGNUM* modulus = RSA_get0_n(rsa);
  len = BN_bn2bin(modulus, buffer);
  obj.modulus = std::vector<BYTE>(len);
  obj.modulus.assign(buffer, buffer + len - 1);

  const BIGNUM* exponent = RSA_get0_e(rsa);
  len = BN_bn2bin(exponent, buffer);
  obj.exponent = std::vector<BYTE>(len);
  obj.exponent.assign(buffer, buffer + len - 1);

  EVP_PKEY_free(pubkey);
  RSA_free(rsa);

  return obj;
}

}  // namespace crypto
