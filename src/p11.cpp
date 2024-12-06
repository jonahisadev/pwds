#include "p11.hpp"

#include <cstddef>
#include <cstdlib>
#include <format>
#include <ios>
#include <iostream>
#include <stdexcept>

#include "pkcs11/pkcs11t.h"
#include "src/base64.hpp"
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

bool P11Module::createKey(const std::string& name, KeyType type,
                          std::size_t bits)
{
  if (type == KeyType::AES) {
    return generateSymmetricKey(name, type, bits);
  }
  return false;
}

bool P11Module::generateSymmetricKey(const std::string& name, KeyType type,
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

std::optional<Key> P11Module::findKey(const std::string& name)
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

  return std::make_optional<Key>(keyHandle, name);
}

void P11Module::deleteKey(const std::string& name)
{
  auto key = findKey(name);
  if (!key.has_value()) {
    return;
  }
  deleteKey(*key);
}

void P11Module::deleteKey(const Key& key)
{
  CK_RV rv = m_p11->C_DestroyObject(m_session, key.getHandle());
  if (rv != CKR_OK) {
    std::cerr << "Could not delete key from handle " << std::hex
              << key.getHandle() << std::endl;
  }
}

void P11Module::importCertificate(const std::string& name,
                                  const std::string& pem)
{
  auto data = crypto::cert_der_from_pem(pem);
  CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType = CKC_X_509;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BBOOL falseValue = CK_FALSE;
  auto* derPtr = data.all.data();
  auto* subjectPtr = data.subject.data();
  const char* label = name.c_str();

  CK_ATTRIBUTE pTemplate[] = {
      {CKA_CLASS, &certClass, sizeof(certClass)},
      {CKA_TOKEN, &falseValue, sizeof(falseValue)},
      {CKA_PRIVATE, &falseValue, sizeof(falseValue)},
      {CKA_MODIFIABLE, &trueValue, sizeof(trueValue)},
      {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
      {CKA_LABEL, (char*)label, name.length()},
      {CKA_VALUE, derPtr, data.all.size()},
      {CKA_SUBJECT, subjectPtr, data.subject.size()}};

  CK_OBJECT_HANDLE certObject;
  CK_RV rv = m_p11->C_CreateObject(m_session, pTemplate, 8, &certObject);
  if (rv != CKR_OK) {
    std::cerr << "Error: 0x" << std::hex << std::uppercase << rv << std::endl;
    throw std::runtime_error("Could not import certificate");
  }

  auto pubKey = crypto::extract_pub_from_cert(data);
  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  auto* modulusPtr = pubKey.modulus.data();
  auto* exponentPtr = pubKey.exponent.data();

  CK_ATTRIBUTE pTemplate2[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_TOKEN, &trueValue, sizeof(trueValue)},
      {CKA_LABEL, (CK_VOID_PTR)label, name.length()},
      {CKA_WRAP, &trueValue, sizeof(trueValue)},
      {CKA_MODULUS, &modulusPtr, pubKey.modulus.size()},
      {CKA_PUBLIC_EXPONENT, &exponentPtr, pubKey.exponent.size()}};

  CK_OBJECT_HANDLE pubKeyObject;
  rv = m_p11->C_CreateObject(m_session, pTemplate2, 7, &pubKeyObject);
  if (rv != CKR_OK) {
    std::cerr << "Error: 0x" << std::hex << std::uppercase << rv << std::endl;
    throw std::runtime_error("Could not import public key from certificate");
  }
}

std::optional<std::string> P11Module::encrypt(const Key& key, char* data,
                                              std::size_t dataLen,
                                              std::vector<CK_BYTE> iv)
{
  CK_MECHANISM mechanism = {CKM_AES_CBC_PAD, iv.data(), 16};
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

  std::string encoded = base64_encode(encryptedBytes.data(), encryptedLen);
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

  auto encryptedBytes = base64_decode(data);

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

std::vector<CK_BYTE> P11Module::generateRandomBytes(std::size_t size)
{
  // TODO: C_SeedRandom
  std::vector<CK_BYTE> bytes(size);
  CK_RV rv = m_p11->C_GenerateRandom(m_session, bytes.data(), size);
  if (rv != CKR_OK) {
    std::cerr << "Could not generate random data" << std::endl;
  }
  return bytes;
}
