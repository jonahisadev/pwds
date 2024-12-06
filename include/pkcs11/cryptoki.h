/* cryptoki.h include file for PKCS #11. */

#ifndef __CRYPTOKI_H__
#define __CRYPTOKI_H__

/* Unix platform */
#define CK_PTR *
#define NULL_PTR 0
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#include "pkcs11.h"

#endif  // __CRYPTOKI_H__
