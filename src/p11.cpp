#include "p11.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <ios>
#include <iostream>
#include <stdexcept>

#include "base64/base64.hpp"
#include "pkcs11/pkcs11t.h"
#include "src/crypto.hpp"

P11Module::P11Module()
{
  CK_RV rv = C_GetFunctionList(&m_p11);
  if (rv != CKR_OK) {
    std::cerr << "Error getting function list: " << std::hex << rv << std::endl;
    throw new std::runtime_error("Could not get p11 funcs");
  }
  m_session = NULL_PTR;
}

void P11Module::login(const std::string& nssPath, const std::string& pin)
{
  auto slots = login(nssPath);

  if (!pin.empty()) {
    const char* pinCstr = pin.data();
    CK_RV rv = m_p11->C_Login(m_session, CKU_USER, (CK_UTF8CHAR_PTR)pinCstr,
                              pin.length());
    if (rv != CKR_OK) {
      std::cerr << "Error logging in: " << std::hex << rv << std::endl;
      throw new std::runtime_error("Could not log into the P11 module");
    }
  }

  for (auto& slot : slots) {
    std::free(slot.info);
  }
}

std::vector<Slot> P11Module::login(const std::string& nssPath)
{
  std::string str = std::format(
      "configdir='{}' certPrefix='' keyPrefix='' secmod='' flags=0x40",
      nssPath);
  const char* c_str = str.data();

  CK_C_INITIALIZE_ARGS initArgs = {};
  initArgs.flags = CKF_OS_LOCKING_OK;
  initArgs.LibraryParameters = (CK_CHAR_PTR)c_str;
  CK_RV rv = m_p11->C_Initialize(&initArgs);
  if (rv != CKR_OK) {
    std::cerr << "Error initializing P11: " << std::hex << rv << std::endl;
    throw new std::runtime_error("Could not initialize P11 module");
  }

  auto slots = load_slots();
  create_session(slots[1].id);

  return slots;
}

std::vector<Slot> P11Module::load_slots()
{
  CK_ULONG slotCount;
  CK_RV rv = m_p11->C_GetSlotList(1, NULL_PTR, &slotCount);
  if (rv != CKR_OK) {
    std::cerr << "Could not get slots" << std::endl;
    return {};
  }

  std::vector<CK_SLOT_ID> slotIds = std::vector<CK_SLOT_ID>(slotCount);
  rv = m_p11->C_GetSlotList(1, slotIds.data(), &slotCount);
  if (rv != CKR_OK) {
    std::cerr << "Could not get slots" << std::endl;
    return {};
  }

  std::vector<Slot> slots;
  for (std::size_t i = 0; i < slotCount; i++) {
    CK_SLOT_INFO_PTR slotInfo =
        (CK_SLOT_INFO_PTR)std::malloc(sizeof(CK_SLOT_INFO));
    CK_RV rv = m_p11->C_GetSlotInfo(slotIds.at(i), slotInfo);
    if (rv != CKR_OK) {
      std::cerr << "Error getting slot info " << rv << std::endl;
      return {};
    }

    Slot slot;
    slot.id = slotIds.at(i);
    slot.info = slotInfo;
    slots.push_back(slot);
  }

  return slots;
}

void P11Module::create_session(CK_SLOT_ID slotId)
{
  CK_RV rv = m_p11->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, &m_session);
  if (rv != CKR_OK) {
    std::cerr << "Could not open session" << std::endl;
    return;
  }
}

void P11Module::logout()
{
  CK_RV rv = m_p11->C_CloseSession(m_session);
  if (rv != CKR_OK) {
    std::cerr << "Error logging out" << std::endl;
    return;
  }
}

bool P11Module::create_key(const std::string& name, KeyType type,
                           std::size_t bits)
{
  if (type == KeyType::AES) {
    return generate_symmetric_key(name, type, bits);
  }
  else if (type == KeyType::RSA) {
    std::cerr << "Generated RSA keypair is not supported at this time"
              << std::endl;
    return false;
  }
  return false;
}

bool P11Module::generate_symmetric_key(const std::string& name, KeyType type,
                                       std::size_t bits)
{
  CK_MECHANISM mechanism = {};
  CK_KEY_TYPE keyType;

  switch (type) {
    case KeyType::AES:
      mechanism = {CKM_AES_KEY_GEN, NULL_PTR, 0};
      keyType = CKK_AES;
      break;
    default:
      return false;
  }

  const char* label = name.c_str();
  CK_OBJECT_CLASS ckClass = CKO_SECRET_KEY;
  CK_ULONG valueLen = (bits / 8);
  CK_BBOOL trueValue = CK_TRUE;
  CK_ATTRIBUTE pTemplate[] = {{CKA_CLASS, &ckClass, sizeof(ckClass)},
                              {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                              {CKA_TOKEN, &trueValue, sizeof(trueValue)},
                              {CKA_LABEL, (char*)label, name.length()},
                              {CKA_ENCRYPT, &trueValue, sizeof(trueValue)},
                              {CKA_DECRYPT, &trueValue, sizeof(trueValue)},
                              {CKA_VALUE_LEN, &valueLen, sizeof(valueLen)},
                              {CKA_EXTRACTABLE, &trueValue, sizeof(trueValue)}};

  CK_OBJECT_HANDLE keyHandle;
  CK_RV rv =
      m_p11->C_GenerateKey(m_session, &mechanism, pTemplate, 8, &keyHandle);
  if (rv != CKR_OK) {
    std::cerr << "Could not generate key " << std::hex << rv << std::endl;
    return false;
  }

  return true;
}

std::optional<Key> P11Module::find_key(const std::string& name)
{
  const char* nameCstr = name.c_str();
  CK_ATTRIBUTE searchParams[] = {{CKA_LABEL, (char*)nameCstr, name.length()}};
  CK_RV rv = m_p11->C_FindObjectsInit(m_session, searchParams, 1);
  if (rv != CKR_OK) {
    std::cerr << "Could not initialize key search " << std::hex << rv
              << std::endl;
    return {};
  }

  CK_OBJECT_HANDLE keyHandle;
  CK_ULONG keysFound;
  rv = m_p11->C_FindObjects(m_session, &keyHandle, 1, &keysFound);
  if (rv != CKR_OK) {
    std::cerr << "Could not execute key search " << std::hex << rv << std::endl;
    return {};
  }

  if (keysFound == 0) {
    std::cerr << "Could not find key by alias " << name << std::endl;
    return {};
  }

  rv = m_p11->C_FindObjectsFinal(m_session);
  if (rv != CKR_OK) {
    std::cerr << "Could not finish key search " << std::hex << rv << std::endl;
    return {};
  }

  CK_ATTRIBUTE extraParams[] = {{CKA_KEY_TYPE, nullptr, 0}};
  rv = m_p11->C_GetAttributeValue(m_session, keyHandle, extraParams, 1);
  if (rv != CKR_OK) {
    std::cerr << "Could not find key type" << std::hex << rv << std::endl;
    return {};
  }
  CK_ULONG sessionKeyType = 0;
  extraParams[0].pValue = &sessionKeyType;
  rv = m_p11->C_GetAttributeValue(m_session, keyHandle, extraParams, 1);
  if (rv != CKR_OK) {
    std::cerr << "Could not find key type" << std::hex << rv << std::endl;
    return {};
  }

  KeyType type;
  switch (sessionKeyType) {
    case CKK_AES:
      type = KeyType::AES;
      break;
    case CKK_RSA:
      type = KeyType::RSA;
      break;
  }

  return std::make_optional<Key>(keyHandle, type, name);
}

void P11Module::delete_key(const std::string& name)
{
  auto key = find_key(name);
  if (!key.has_value()) {
    return;
  }
  delete_key(*key);
}

void P11Module::delete_key(const Key& key)
{
  CK_RV rv = m_p11->C_DestroyObject(m_session, key.getHandle());
  if (rv != CKR_OK) {
    std::cerr << "Could not delete key from handle " << std::hex
              << key.getHandle() << std::endl;
  }
}

void P11Module::import_rsa_public_key(const std::string& name,
                                      const Botan::RSA_PublicKey& public_key)
{
  CK_OBJECT_CLASS object_class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_BBOOL false_val = CK_FALSE;
  CK_BBOOL true_val = CK_TRUE;
  const char* label = name.c_str();

  auto modulus = public_key.get_n().serialize();
  auto exponent = public_key.get_e().serialize();

  CK_ATTRIBUTE p_template[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_TOKEN, &false_val, sizeof(false_val)},
      {CKA_LABEL, (char*)label, name.length()},
      {CKA_ENCRYPT, &true_val, sizeof(true_val)},
      {CKA_MODULUS, modulus.data(), modulus.size()},
      {CKA_PUBLIC_EXPONENT, exponent.data(), exponent.size()}};

  CK_OBJECT_HANDLE key_object;
  CK_RV rv = m_p11->C_CreateObject(m_session, p_template, 7, &key_object);
  if (rv != CKR_OK) {
    std::cerr << "Error: 0x" << std::hex << std::uppercase << rv << std::endl;
    throw std::runtime_error("Could not import public key");
  }
}

void P11Module::import_certificate(const std::string& name,
                                   const std::string& pemPath)
{
  auto certificate = pwds::crypto::load_cert_pem(pemPath);
  CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType = CKC_X_509;
  CK_BBOOL falseValue = CK_FALSE;
  CK_BBOOL trueValue = CK_TRUE;
  auto derEncoded = certificate.BER_encode();
  auto subjectEncoded = certificate.raw_subject_dn();
  auto issuerEncoded = certificate.raw_issuer_dn();
  auto serialNumber = certificate.serial_number();
  const char* label = name.c_str();

  CK_ATTRIBUTE pTemplate[] = {
      {CKA_CLASS, &certClass, sizeof(certClass)},
      {CKA_TOKEN, &trueValue, sizeof(falseValue)},
      {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
      {CKA_LABEL, (char*)label, name.length()},
      {CKA_VALUE, derEncoded.data(), derEncoded.size()},
      {CKA_SUBJECT, subjectEncoded.data(), subjectEncoded.size()},
      {CKA_ISSUER, issuerEncoded.data(), issuerEncoded.size()},
      {CKA_SERIAL_NUMBER, serialNumber.data(), serialNumber.size()}};

  CK_OBJECT_HANDLE certObject;
  CK_RV rv = m_p11->C_CreateObject(m_session, pTemplate, 8, &certObject);
  if (rv != CKR_OK) {
    std::cerr << "Error: 0x" << std::hex << std::uppercase << rv << std::endl;
    throw std::runtime_error("Could not import certificate");
  }
}

std::optional<std::string> P11Module::encrypt(const Key& key, char* data,
                                              std::size_t dataLen,
                                              std::vector<CK_BYTE> iv)
{
  CK_MECHANISM mechanism;
  if (key.getKeyType() == KeyType::AES) {
    mechanism = {CKM_AES_CBC_PAD, iv.data(), 16};
  }
  else if (key.getKeyType() == KeyType::RSA) {
    CK_RSA_PKCS_OAEP_PARAMS params = {CKM_SHA_1, CKG_MGF1_SHA1, 1, nullptr, 0};
    mechanism = {CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  }
  else {
    return {};
  }

  CK_RV rv = m_p11->C_EncryptInit(m_session, &mechanism, key.getHandle());
  if (rv != CKR_OK) {
    std::cerr << "Could not initialize encryption " << std::hex << rv
              << std::endl;
    return {};
  }

  CK_ULONG encryptedLen;
  rv = m_p11->C_Encrypt(m_session, (CK_BYTE_PTR)data, dataLen, NULL,
                        &encryptedLen);
  if (rv != CKR_OK) {
    std::cerr << "Could not encrypt(1) " << std::hex << rv << std::endl;
    return {};
  }

  std::vector<CK_BYTE> encryptedBytes(encryptedLen);
  rv = m_p11->C_Encrypt(m_session, (CK_BYTE_PTR)data, dataLen,
                        encryptedBytes.data(), &encryptedLen);
  if (rv != CKR_OK) {
    std::cerr << "Could not encrypt(2) " << std::hex << rv << std::endl;
    return {};
  }

  std::string encoded;
  if (key.getKeyType() == KeyType::AES) {
    encoded = base64::encode_into<std::string>(
        encryptedBytes.begin(), encryptedBytes.begin() + encryptedLen);
  }
  else if (key.getKeyType() == KeyType::RSA) {
    encoded = base64::encode_into<std::string>(encryptedBytes.begin(),
                                               encryptedBytes.end());
  }

  return encoded;
}

std::optional<std::string> P11Module::decrypt(const Key& key, std::string data,
                                              std::vector<CK_BYTE> iv)
{
  CK_MECHANISM mechanism = {CKM_AES_CBC_PAD, iv.data(), 16};
  CK_RV rv = m_p11->C_DecryptInit(m_session, &mechanism, key.getHandle());
  if (rv != CKR_OK) {
    std::cerr << "Could not initialize decryption " << std::hex << rv
              << std::endl;
    return {};
  }

  auto encryptedBytes = base64::decode_into<std::vector<uint8_t>>(data);

  CK_ULONG decryptedLen;
  rv = m_p11->C_Decrypt(m_session, (CK_BYTE_PTR)encryptedBytes.data(),
                        encryptedBytes.size(), NULL, &decryptedLen);
  if (rv != CKR_OK) {
    std::cerr << "Could not decrypt(1) " << std::hex << rv << std::endl;
    return {};
  }

  std::vector<CK_BYTE> decryptedBytes(decryptedLen);
  rv = m_p11->C_Decrypt(m_session, (CK_BYTE_PTR)encryptedBytes.data(),
                        encryptedBytes.size(), decryptedBytes.data(),
                        &decryptedLen);
  if (rv != CKR_OK) {
    std::cerr << "Could not decrypt(2) " << std::hex << rv << std::endl;
    return {};
  }

  return std::string(reinterpret_cast<const char*>(decryptedBytes.data()),
                     decryptedLen);
}

std::vector<CK_BYTE> P11Module::generate_random_bytes(std::size_t size)
{
  // TODO: C_SeedRandom
  std::vector<CK_BYTE> bytes(size);
  CK_RV rv = m_p11->C_GenerateRandom(m_session, bytes.data(), size);
  if (rv != CKR_OK) {
    std::cerr << "Could not generate random data" << std::endl;
  }
  return bytes;
}
