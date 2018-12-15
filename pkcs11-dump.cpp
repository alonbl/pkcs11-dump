/*
 * Copyright (c) 2005-2008 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING.GPL included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PACKAGE_NAME
#define PACKAGE_NAME "pkcs11-dump"
#define PACKAGE_VERSION "unknown"
#endif

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#else
#include <unistd.h>
#include <dlfcn.h>
#include <openssl/x509.h>
#endif

#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "pkcs11.h"

#if defined(_WIN32)
#define PKCS11_MODULE_HANDLE HMODULE
#else
#define PKCS11_MODULE_HANDLE void *
#endif

#if !defined(IN)
#define IN
#endif

#if !defined(OUT)
#define OUT
#endif

#if !defined(_WIN32)
#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *pkcs11_openssl_d2i_t;
#else
typedef const unsigned char *pkcs11_openssl_d2i_t;
#endif
#endif

typedef enum {
	attrtypeUnknown,
	attrtypeString,
	attrtypeByteArray,
	attrtypeSubject,
	attrtypeSubject1,
	attrtypeBigInteger,
	attrtypeCK_BBOOL,
	attrtypeCK_DATE,
	attrtypeCK_ULONG,
	attrtypeCK_CERTIFICATE_TYPE,
	attrtypeCK_KEY_TYPE,
	attrtypeCK_MECHANISM_TYPE,
	attrtypeCK_OBJECT_CLASS,
	attrtypeCK_HW_FEATURE_TYPE,
	attrtypeCK_CHAR,
	attrtypeCK_ATTRIBUTE_PTR,
	attrtypeCK_MECHANISM_TYPE_PTR
} AttributeType;

typedef struct {
	int nId;
	const char *szName;
	AttributeType attrtypeType;
	int nSize;
} AttributeDescription;

class CEGeneral {
public:
	CEGeneral (
		IN const std::string &str
	) : m_str(str) {};

public:
	std::string m_str;
};

class CEPKCS11 {
public:
	CEPKCS11 (
		IN const std::string &str,
		IN const CK_RV rv
	) : m_str(str), m_rv(rv) {};

public:
	std::string m_str;
	CK_RV m_rv;
};

const AttributeDescription attrdescAttributes[] = {
	{CKA_CLASS, "CKA_CLASS", attrtypeCK_OBJECT_CLASS, 0},
	{CKA_TOKEN, "CKA_TOKEN", attrtypeCK_BBOOL, 0},
	{CKA_PRIVATE, "CKA_PRIVATE", attrtypeCK_BBOOL, 0},
	{CKA_LABEL, "CKA_LABEL", attrtypeString, 0},
	{CKA_APPLICATION, "CKA_APPLICATION", attrtypeString, 0},
	{CKA_VALUE, "CKA_VALUE", attrtypeByteArray, 16},
	{CKA_OBJECT_ID, "CKA_OBJECT_ID", attrtypeByteArray, 0},
	{CKA_CERTIFICATE_TYPE, "CKA_CERTIFICATE_TYPE", attrtypeCK_CERTIFICATE_TYPE, 0},
	{CKA_ISSUER, "CKA_ISSUER", attrtypeSubject, 0},
	{CKA_SERIAL_NUMBER, "CKA_SERIAL_NUMBER", attrtypeByteArray, 0},
	{CKA_AC_ISSUER, "CKA_AC_ISSUER", attrtypeSubject1, 0},
	{CKA_OWNER, "CKA_OWNER", attrtypeSubject1, 0},
	{CKA_ATTR_TYPES, "CKA_ATTR_TYPES", attrtypeByteArray, 0},
	{CKA_TRUSTED, "CKA_TRUSTED", attrtypeCK_BBOOL, 0},
	{CKA_CERTIFICATE_CATEGORY, "CKA_CERTIFICATE_CATEGORY", attrtypeCK_ULONG, 0},
	{CKA_JAVA_MIDP_SECURITY_DOMAIN, "CKA_JAVA_MIDP_SECURITY_DOMAIN", attrtypeCK_ULONG, 0},
	{CKA_URL, "CKA_URL", attrtypeString, 0},
	{CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", attrtypeByteArray, 0},
	{CKA_HASH_OF_ISSUER_PUBLIC_KEY, "CKA_HASH_OF_ISSUER_PUBLIC_KEY", attrtypeByteArray, 0},
	{CKA_CHECK_VALUE, "CKA_CHECK_VALUE", attrtypeByteArray, 0},
	{CKA_KEY_TYPE, "CKA_KEY_TYPE", attrtypeCK_KEY_TYPE, 0},
	{CKA_SUBJECT, "CKA_SUBJECT", attrtypeSubject, 0},
	{CKA_ID, "CKA_ID", attrtypeByteArray, 0},
	{CKA_SENSITIVE, "CKA_SENSITIVE", attrtypeCK_BBOOL, 0},
	{CKA_ENCRYPT, "CKA_ENCRYPT", attrtypeCK_BBOOL, 0},
	{CKA_DECRYPT, "CKA_DECRYPT", attrtypeCK_BBOOL, 0},
	{CKA_WRAP, "CKA_WRAP", attrtypeCK_BBOOL, 0},
	{CKA_UNWRAP, "CKA_UNWRAP", attrtypeCK_BBOOL, 0},
	{CKA_SIGN, "CKA_SIGN", attrtypeCK_BBOOL, 0},
	{CKA_SIGN_RECOVER, "CKA_SIGN_RECOVER", attrtypeCK_BBOOL, 0},
	{CKA_VERIFY, "CKA_VERIFY", attrtypeCK_BBOOL, 0},
	{CKA_VERIFY_RECOVER, "CKA_VERIFY_RECOVER", attrtypeCK_BBOOL, 0},
	{CKA_DERIVE, "CKA_DERIVE", attrtypeCK_BBOOL, 0},
	{CKA_START_DATE, "CKA_START_DATE", attrtypeCK_DATE, 0},
	{CKA_END_DATE, "CKA_END_DATE", attrtypeCK_DATE, 0},
	{CKA_MODULUS, "CKA_MODULUS", attrtypeBigInteger, 0},
	{CKA_MODULUS_BITS, "CKA_MODULUS_BITS", attrtypeCK_ULONG, 0},
	{CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT", attrtypeBigInteger, 0},
	{CKA_PRIVATE_EXPONENT, "CKA_PRIVATE_EXPONENT", attrtypeBigInteger, 0},
	{CKA_PRIME_1, "CKA_PRIME_1", attrtypeBigInteger, 0},
	{CKA_PRIME_2, "CKA_PRIME_2", attrtypeBigInteger, 0},
	{CKA_EXPONENT_1, "CKA_EXPONENT_1", attrtypeBigInteger, 0},
	{CKA_EXPONENT_2, "CKA_EXPONENT_2", attrtypeBigInteger, 0},
	{CKA_COEFFICIENT, "CKA_COEFFICIENT", attrtypeBigInteger, 0},
	{CKA_PRIME, "CKA_PRIME", attrtypeBigInteger, 0},
	{CKA_SUBPRIME, "CKA_SUBPRIME", attrtypeBigInteger, 0},
	{CKA_BASE, "CKA_BASE", attrtypeBigInteger, 0},
	{CKA_PRIME_BITS, "CKA_PRIME_BITS", attrtypeCK_ULONG, 0},
//OS	{CKA_SUBPRIME_BITS, "CKA_SUBPRIME_BITS", attrtypeCK_ULONG, 0},
	{CKA_SUB_PRIME_BITS, "CKA_SUB_PRIME_BITS", attrtypeCK_ULONG, 0},
	{CKA_VALUE_BITS, "CKA_VALUE_BITS", attrtypeCK_ULONG, 0},
	{CKA_VALUE_LEN, "CKA_VALUE_LEN", attrtypeCK_ULONG, 0},
	{CKA_EXTRACTABLE, "CKA_EXTRACTABLE", attrtypeCK_BBOOL, 0},
	{CKA_LOCAL, "CKA_LOCAL", attrtypeCK_BBOOL, 0},
	{CKA_NEVER_EXTRACTABLE, "CKA_NEVER_EXTRACTABLE", attrtypeCK_BBOOL, 0},
	{CKA_ALWAYS_SENSITIVE, "CKA_ALWAYS_SENSITIVE", attrtypeCK_BBOOL, 0},
	{CKA_KEY_GEN_MECHANISM, "CKA_KEY_GEN_MECHANISM", attrtypeCK_MECHANISM_TYPE, 0},
	{CKA_MODIFIABLE, "CKA_MODIFIABLE", attrtypeCK_BBOOL, 0},
	{CKA_ECDSA_PARAMS, "CKA_ECDSA_PARAMS", attrtypeByteArray, 0},
	{CKA_EC_PARAMS, "CKA_EC_PARAMS", attrtypeByteArray, 0},
	{CKA_EC_POINT, "CKA_EC_POINT", attrtypeByteArray, 0},
	{CKA_SECONDARY_AUTH, "CKA_SECONDARY_AUTH", attrtypeUnknown, 0},
	{CKA_AUTH_PIN_FLAGS, "CKA_AUTH_PIN_FLAGS", attrtypeUnknown, 0},
	{CKA_ALWAYS_AUTHENTICATE, "CKA_ALWAYS_AUTHENTICATE", attrtypeCK_BBOOL, 0},
	{CKA_WRAP_WITH_TRUSTED, "CKA_WRAP_WITH_TRUSTED", attrtypeCK_BBOOL, 0},
	{CKA_WRAP_TEMPLATE, "CKA_WRAP_TEMPLATE", attrtypeCK_ATTRIBUTE_PTR, 0},
	{CKA_UNWRAP_TEMPLATE, "CKA_UNWRAP_TEMPLATE", attrtypeCK_ATTRIBUTE_PTR, 0},
	{CKA_HW_FEATURE_TYPE, "CKA_HW_FEATURE_TYPE", attrtypeCK_HW_FEATURE_TYPE, 0},
	{CKA_RESET_ON_INIT, "CKA_RESET_ON_INIT", attrtypeCK_BBOOL, 0},
	{CKA_HAS_RESET, "CKA_HAS_RESET", attrtypeCK_BBOOL, 0},
	{CKA_PIXEL_X, "CKA_PIXEL_X", attrtypeCK_ULONG, 0},
	{CKA_PIXEL_Y, "CKA_PIXEL_Y", attrtypeCK_ULONG, 0},
	{CKA_RESOLUTION, "CKA_RESOLUTION", attrtypeCK_ULONG, 0},
	{CKA_CHAR_ROWS, "CKA_CHAR_ROWS", attrtypeCK_ULONG, 0},
	{CKA_CHAR_COLUMNS, "CKA_CHAR_COLUMNS", attrtypeCK_ULONG, 0},
	{CKA_COLOR, "CKA_COLOR", attrtypeCK_BBOOL, 0},
	{CKA_BITS_PER_PIXEL, "CKA_BITS_PER_PIXEL", attrtypeCK_ULONG, 0},
	{CKA_CHAR_SETS, "CKA_CHAR_SETS", attrtypeString, 0},
	{CKA_ENCODING_METHODS, "CKA_ENCODING_METHODS", attrtypeString, 0},
	{CKA_MIME_TYPES, "CKA_MIME_TYPES", attrtypeString, 0},
	{CKA_MECHANISM_TYPE, "CKA_MECHANISM_TYPE", attrtypeCK_MECHANISM_TYPE, 0},
	{CKA_REQUIRED_CMS_ATTRIBUTES, "CKA_REQUIRED_CMS_ATTRIBUTES", attrtypeByteArray, 0},
	{CKA_DEFAULT_CMS_ATTRIBUTES, "CKA_DEFAULT_CMS_ATTRIBUTES", attrtypeByteArray, 0},
	{CKA_SUPPORTED_CMS_ATTRIBUTES, "CKA_SUPPORTED_CMS_ATTRIBUTES", attrtypeByteArray, 0},
	{CKA_ALLOWED_MECHANISMS, "CKA_ALLOWED_MECHANISMS", attrtypeCK_MECHANISM_TYPE_PTR, 0},
	{-1, NULL, attrtypeUnknown, 0}
};

static
std::string
Resolve_CK_OBJECT_CLASS (
	IN const CK_OBJECT_CLASS c
) {
	switch (c) {
		case CKO_DATA: return "CKO_DATA";
		case CKO_CERTIFICATE: return "CKO_CERTIFICATE";
		case CKO_PUBLIC_KEY: return "CKO_PUBLIC_KEY";
		case CKO_PRIVATE_KEY: return "CKO_PRIVATE_KEY";
		case CKO_SECRET_KEY: return "CKO_SECRET_KEY";
		case CKO_HW_FEATURE: return "CKO_HW_FEATURE";
		case CKO_DOMAIN_PARAMETERS: return "CKO_DOMAIN_PARAMETERS";
		case CKO_MECHANISM: return "CKO_MECHANISM";
		case CKO_VENDOR_DEFINED: return "CKO_VENDOR_DEFINED";
		default:
			{
				char szError[1024];
				sprintf (szError, "Unknown CK_OBJECT_CLASS %08lx", c);
				return szError;
			}
	}
}

static
std::string
Resolve_CK_KEY_TYPE (
	IN const CK_KEY_TYPE t
) {
	switch (t) {
		case CKK_RSA: return "CKK_RSA";
		case CKK_DSA: return "CKK_DSA";
		case CKK_DH: return "CKK_DH";
		case CKK_ECDSA: return "CKK_ECDSA";
//		case CKK_EC: return "CKK_EC";
		case CKK_X9_42_DH: return "CKK_X9_42_DH";
		case CKK_KEA: return "CKK_KEA";
		case CKK_GENERIC_SECRET: return "CKK_GENERIC_SECRET";
		case CKK_RC2: return "CKK_RC2";
		case CKK_RC4: return "CKK_RC4";
		case CKK_DES: return "CKK_DES";
		case CKK_DES2: return "CKK_DES2";
		case CKK_DES3: return "CKK_DES3";
		case CKK_CAST: return "CKK_CAST";
		case CKK_CAST3: return "CKK_CAST3";
//OS		case CKK_CAST5: return "CKK_CAST5";
//		case CKK_CAST128: return "CKK_CAST128";
		case CKK_RC5: return "CKK_RC5";
		case CKK_IDEA: return "CKK_IDEA";
		case CKK_SKIPJACK: return "CKK_SKIPJACK";
		case CKK_BATON: return "CKK_BATON";
		case CKK_JUNIPER: return "CKK_JUNIPER";
		case CKK_CDMF: return "CKK_CDMF";
		case CKK_AES: return "CKK_AES";
		case CKK_BLOWFISH: return "CKK_BLOWFISH";
		case CKK_TWOFISH: return "CKK_TWOFISH";
		case CKK_VENDOR_DEFINED: return "CKK_VENDOR_DEFINED";
		default:
			{
				char szError[1024];
				sprintf (szError, "Unknown CK_KEY_TYPE %08lx", t);
				return szError;
			}
	}
}

static
std::string
Resolve_CK_MECHANISM_TYPE (
	IN CK_MECHANISM_TYPE t
) {
	switch (t) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
		case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
		case CKM_RSA_9796: return "CKM_RSA_9796";
		case CKM_RSA_X_509: return "CKM_RSA_X_509";
		case CKM_MD2_RSA_PKCS: return "CKM_MD2_RSA_PKCS";
		case CKM_MD5_RSA_PKCS: return "CKM_MD5_RSA_PKCS";
		case CKM_SHA1_RSA_PKCS: return "CKM_SHA1_RSA_PKCS";
		case CKM_RIPEMD128_RSA_PKCS: return "CKM_RIPEMD128_RSA_PKCS";
		case CKM_RIPEMD160_RSA_PKCS: return "CKM_RIPEMD160_RSA_PKCS";
		case CKM_RSA_PKCS_OAEP: return "CKM_RSA_PKCS_OAEP";
		case CKM_RSA_X9_31_KEY_PAIR_GEN: return "CKM_RSA_X9_31_KEY_PAIR_GEN";
		case CKM_RSA_X9_31: return "CKM_RSA_X9_31";
		case CKM_SHA1_RSA_X9_31: return "CKM_SHA1_RSA_X9_31";
		case CKM_RSA_PKCS_PSS: return "CKM_RSA_PKCS_PSS";
		case CKM_SHA1_RSA_PKCS_PSS: return "CKM_SHA1_RSA_PKCS_PSS";
		case CKM_DSA_KEY_PAIR_GEN: return "CKM_DSA_KEY_PAIR_GEN";
		case CKM_DSA: return "CKM_DSA";
		case CKM_DSA_SHA1: return "CKM_DSA_SHA1";
		case CKM_DH_PKCS_KEY_PAIR_GEN: return "CKM_DH_PKCS_KEY_PAIR_GEN";
		case CKM_DH_PKCS_DERIVE: return "CKM_DH_PKCS_DERIVE";
		case CKM_X9_42_DH_KEY_PAIR_GEN: return "CKM_X9_42_DH_KEY_PAIR_GEN";
		case CKM_X9_42_DH_DERIVE: return "CKM_X9_42_DH_DERIVE";
		case CKM_X9_42_DH_HYBRID_DERIVE: return "CKM_X9_42_DH_HYBRID_DERIVE";
		case CKM_X9_42_MQV_DERIVE: return "CKM_X9_42_MQV_DERIVE";
/*OS
		case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
		case CKM_SHA384_RSA_PKCS: return "CKM_SHA384_RSA_PKCS";
		case CKM_SHA512_RSA_PKCS: return "CKM_SHA512_RSA_PKCS";
		case CKM_SHA256_RSA_PKCS_PSS: return "CKM_SHA256_RSA_PKCS_PSS";
		case CKM_SHA384_RSA_PKCS_PSS: return "CKM_SHA384_RSA_PKCS_PSS";
		case CKM_SHA512_RSA_PKCS_PSS: return "CKM_SHA512_RSA_PKCS_PSS";
*/
		case CKM_RC2_KEY_GEN: return "CKM_RC2_KEY_GEN";
		case CKM_RC2_ECB: return "CKM_RC2_ECB";
		case CKM_RC2_CBC: return "CKM_RC2_CBC";
		case CKM_RC2_MAC: return "CKM_RC2_MAC";
		case CKM_RC2_MAC_GENERAL: return "CKM_RC2_MAC_GENERAL";
		case CKM_RC2_CBC_PAD: return "CKM_RC2_CBC_PAD";
		case CKM_RC4_KEY_GEN: return "CKM_RC4_KEY_GEN";
		case CKM_RC4: return "CKM_RC4";
		case CKM_DES_KEY_GEN: return "CKM_DES_KEY_GEN";
		case CKM_DES_ECB: return "CKM_DES_ECB";
		case CKM_DES_CBC: return "CKM_DES_CBC";
		case CKM_DES_MAC: return "CKM_DES_MAC";
		case CKM_DES_MAC_GENERAL: return "CKM_DES_MAC_GENERAL";
		case CKM_DES_CBC_PAD: return "CKM_DES_CBC_PAD";
		case CKM_DES2_KEY_GEN: return "CKM_DES2_KEY_GEN";
		case CKM_DES3_KEY_GEN: return "CKM_DES3_KEY_GEN";
		case CKM_DES3_ECB: return "CKM_DES3_ECB";
		case CKM_DES3_CBC: return "CKM_DES3_CBC";
		case CKM_DES3_MAC: return "CKM_DES3_MAC";
		case CKM_DES3_MAC_GENERAL: return "CKM_DES3_MAC_GENERAL";
		case CKM_DES3_CBC_PAD: return "CKM_DES3_CBC_PAD";
		case CKM_CDMF_KEY_GEN: return "CKM_CDMF_KEY_GEN";
		case CKM_CDMF_ECB: return "CKM_CDMF_ECB";
		case CKM_CDMF_CBC: return "CKM_CDMF_CBC";
		case CKM_CDMF_MAC: return "CKM_CDMF_MAC";
		case CKM_CDMF_MAC_GENERAL: return "CKM_CDMF_MAC_GENERAL";
		case CKM_CDMF_CBC_PAD: return "CKM_CDMF_CBC_PAD";
/*OS
		case CKM_DES_OFB64: return "CKM_DES_OFB64";
		case CKM_DES_OFB8: return "CKM_DES_OFB8";
		case CKM_DES_CFB64: return "CKM_DES_CFB64";
		case CKM_DES_CFB8: return "CKM_DES_CFB8";
*/
		case CKM_MD2: return "CKM_MD2";
		case CKM_MD2_HMAC: return "CKM_MD2_HMAC";
		case CKM_MD2_HMAC_GENERAL: return "CKM_MD2_HMAC_GENERAL";
		case CKM_MD5: return "CKM_MD5";
		case CKM_MD5_HMAC: return "CKM_MD5_HMAC";
		case CKM_MD5_HMAC_GENERAL: return "CKM_MD5_HMAC_GENERAL";
		case CKM_SHA_1: return "CKM_SHA_1";
		case CKM_SHA_1_HMAC: return "CKM_SHA_1_HMAC";
		case CKM_SHA_1_HMAC_GENERAL: return "CKM_SHA_1_HMAC_GENERAL";
		case CKM_RIPEMD128: return "CKM_RIPEMD128";
		case CKM_RIPEMD128_HMAC: return "CKM_RIPEMD128_HMAC";
		case CKM_RIPEMD128_HMAC_GENERAL: return "CKM_RIPEMD128_HMAC_GENERAL";
		case CKM_RIPEMD160: return "CKM_RIPEMD160";
		case CKM_RIPEMD160_HMAC: return "CKM_RIPEMD160_HMAC";
		case CKM_RIPEMD160_HMAC_GENERAL: return "CKM_RIPEMD160_HMAC_GENERAL";
/*OS
		case CKM_SHA256: return "CKM_SHA256";
		case CKM_SHA256_HMAC: return "CKM_SHA256_HMAC";
		case CKM_SHA256_HMAC_GENERAL: return "CKM_SHA256_HMAC_GENERAL";
		case CKM_SHA384: return "CKM_SHA384";
		case CKM_SHA384_HMAC: return "CKM_SHA384_HMAC";
		case CKM_SHA384_HMAC_GENERAL: return "CKM_SHA384_HMAC_GENERAL";
		case CKM_SHA512: return "CKM_SHA512";
		case CKM_SHA512_HMAC: return "CKM_SHA512_HMAC";
		case CKM_SHA512_HMAC_GENERAL: return "CKM_SHA512_HMAC_GENERAL";
*/
		case CKM_CAST_KEY_GEN: return "CKM_CAST_KEY_GEN";
		case CKM_CAST_ECB: return "CKM_CAST_ECB";
		case CKM_CAST_CBC: return "CKM_CAST_CBC";
		case CKM_CAST_MAC: return "CKM_CAST_MAC";
		case CKM_CAST_MAC_GENERAL: return "CKM_CAST_MAC_GENERAL";
		case CKM_CAST_CBC_PAD: return "CKM_CAST_CBC_PAD";
		case CKM_CAST3_KEY_GEN: return "CKM_CAST3_KEY_GEN";
		case CKM_CAST3_ECB: return "CKM_CAST3_ECB";
		case CKM_CAST3_CBC: return "CKM_CAST3_CBC";
		case CKM_CAST3_MAC: return "CKM_CAST3_MAC";
		case CKM_CAST3_MAC_GENERAL: return "CKM_CAST3_MAC_GENERAL";
		case CKM_CAST3_CBC_PAD: return "CKM_CAST3_CBC_PAD";
		case CKM_CAST5_KEY_GEN: return "CKM_CAST5_KEY_GEN";
//		case CKM_CAST128_KEY_GEN: return "CKM_CAST128_KEY_GEN";
		case CKM_CAST5_ECB: return "CKM_CAST5_ECB";
//		case CKM_CAST128_ECB: return "CKM_CAST128_ECB";
		case CKM_CAST5_CBC: return "CKM_CAST5_CBC";
//		case CKM_CAST128_CBC: return "CKM_CAST128_CBC";
		case CKM_CAST5_MAC: return "CKM_CAST5_MAC";
//		case CKM_CAST128_MAC: return "CKM_CAST128_MAC";
		case CKM_CAST5_MAC_GENERAL: return "CKM_CAST5_MAC_GENERAL";
//		case CKM_CAST128_MAC_GENERAL: return "CKM_CAST128_MAC_GENERAL";
		case CKM_CAST5_CBC_PAD: return "CKM_CAST5_CBC_PAD";
//		case CKM_CAST128_CBC_PAD: return "CKM_CAST128_CBC_PAD";
		case CKM_RC5_KEY_GEN: return "CKM_RC5_KEY_GEN";
		case CKM_RC5_ECB: return "CKM_RC5_ECB";
		case CKM_RC5_CBC: return "CKM_RC5_CBC";
		case CKM_RC5_MAC: return "CKM_RC5_MAC";
		case CKM_RC5_MAC_GENERAL: return "CKM_RC5_MAC_GENERAL";
		case CKM_RC5_CBC_PAD: return "CKM_RC5_CBC_PAD";
		case CKM_IDEA_KEY_GEN: return "CKM_IDEA_KEY_GEN";
		case CKM_IDEA_ECB: return "CKM_IDEA_ECB";
		case CKM_IDEA_CBC: return "CKM_IDEA_CBC";
		case CKM_IDEA_MAC: return "CKM_IDEA_MAC";
		case CKM_IDEA_MAC_GENERAL: return "CKM_IDEA_MAC_GENERAL";
		case CKM_IDEA_CBC_PAD: return "CKM_IDEA_CBC_PAD";
		case CKM_GENERIC_SECRET_KEY_GEN: return "CKM_GENERIC_SECRET_KEY_GEN";
		case CKM_CONCATENATE_BASE_AND_KEY: return "CKM_CONCATENATE_BASE_AND_KEY";
		case CKM_CONCATENATE_BASE_AND_DATA: return "CKM_CONCATENATE_BASE_AND_DATA";
		case CKM_CONCATENATE_DATA_AND_BASE: return "CKM_CONCATENATE_DATA_AND_BASE";
		case CKM_XOR_BASE_AND_DATA: return "CKM_XOR_BASE_AND_DATA";
		case CKM_EXTRACT_KEY_FROM_KEY: return "CKM_EXTRACT_KEY_FROM_KEY";
		case CKM_SSL3_PRE_MASTER_KEY_GEN: return "CKM_SSL3_PRE_MASTER_KEY_GEN";
		case CKM_SSL3_MASTER_KEY_DERIVE: return "CKM_SSL3_MASTER_KEY_DERIVE";
		case CKM_SSL3_KEY_AND_MAC_DERIVE: return "CKM_SSL3_KEY_AND_MAC_DERIVE";
		case CKM_SSL3_MASTER_KEY_DERIVE_DH: return "CKM_SSL3_MASTER_KEY_DERIVE_DH";
		case CKM_TLS_PRE_MASTER_KEY_GEN: return "CKM_TLS_PRE_MASTER_KEY_GEN";
		case CKM_TLS_MASTER_KEY_DERIVE: return "CKM_TLS_MASTER_KEY_DERIVE";
		case CKM_TLS_KEY_AND_MAC_DERIVE: return "CKM_TLS_KEY_AND_MAC_DERIVE";
		case CKM_TLS_MASTER_KEY_DERIVE_DH: return "CKM_TLS_MASTER_KEY_DERIVE_DH";
//OS		case CKM_TLS_PRF: return "CKM_TLS_PRF";
		case CKM_SSL3_MD5_MAC: return "CKM_SSL3_MD5_MAC";
		case CKM_SSL3_SHA1_MAC: return "CKM_SSL3_SHA1_MAC";
		case CKM_MD5_KEY_DERIVATION: return "CKM_MD5_KEY_DERIVATION";
		case CKM_MD2_KEY_DERIVATION: return "CKM_MD2_KEY_DERIVATION";
		case CKM_SHA1_KEY_DERIVATION: return "CKM_SHA1_KEY_DERIVATION";
/*OS
		case CKM_SHA256_KEY_DERIVATION: return "CKM_SHA256_KEY_DERIVATION";
		case CKM_SHA384_KEY_DERIVATION: return "CKM_SHA384_KEY_DERIVATION";
		case CKM_SHA512_KEY_DERIVATION: return "CKM_SHA512_KEY_DERIVATION";
*/
		case CKM_PBE_MD2_DES_CBC: return "CKM_PBE_MD2_DES_CBC";
		case CKM_PBE_MD5_DES_CBC: return "CKM_PBE_MD5_DES_CBC";
		case CKM_PBE_MD5_CAST_CBC: return "CKM_PBE_MD5_CAST_CBC";
		case CKM_PBE_MD5_CAST3_CBC: return "CKM_PBE_MD5_CAST3_CBC";
		case CKM_PBE_MD5_CAST5_CBC: return "CKM_PBE_MD5_CAST5_CBC";
//		case CKM_PBE_MD5_CAST128_CBC: return "CKM_PBE_MD5_CAST128_CBC";
		case CKM_PBE_SHA1_CAST5_CBC: return "CKM_PBE_SHA1_CAST5_CBC";
//		case CKM_PBE_SHA1_CAST128_CBC: return "CKM_PBE_SHA1_CAST128_CBC";
		case CKM_PBE_SHA1_RC4_128: return "CKM_PBE_SHA1_RC4_128";
		case CKM_PBE_SHA1_RC4_40: return "CKM_PBE_SHA1_RC4_40";
		case CKM_PBE_SHA1_DES3_EDE_CBC: return "CKM_PBE_SHA1_DES3_EDE_CBC";
		case CKM_PBE_SHA1_DES2_EDE_CBC: return "CKM_PBE_SHA1_DES2_EDE_CBC";
		case CKM_PBE_SHA1_RC2_128_CBC: return "CKM_PBE_SHA1_RC2_128_CBC";
		case CKM_PBE_SHA1_RC2_40_CBC: return "CKM_PBE_SHA1_RC2_40_CBC";
		case CKM_PKCS5_PBKD2: return "CKM_PKCS5_PBKD2";
		case CKM_PBA_SHA1_WITH_SHA1_HMAC: return "CKM_PBA_SHA1_WITH_SHA1_HMAC";
/*OS
		case CKM_WTLS_PRE_MASTER_KEY_GEN: return "CKM_WTLS_PRE_MASTER_KEY_GEN";
		case CKM_WTLS_MASTER_KEY_DERIVE: return "CKM_WTLS_MASTER_KEY_DERIVE";
//		case CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC: return "CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC";
		case CKM_WTLS_PRF: return "CKM_WTLS_PRF";
		case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: return "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
		case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: return "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
*/
		case CKM_KEY_WRAP_LYNKS: return "CKM_KEY_WRAP_LYNKS";
		case CKM_KEY_WRAP_SET_OAEP: return "CKM_KEY_WRAP_SET_OAEP";
//OS		case CKM_CMS_SIG: return "CKM_CMS_SIG";
		case CKM_SKIPJACK_KEY_GEN: return "CKM_SKIPJACK_KEY_GEN";
		case CKM_SKIPJACK_ECB64: return "CKM_SKIPJACK_ECB64";
		case CKM_SKIPJACK_CBC64: return "CKM_SKIPJACK_CBC64";
		case CKM_SKIPJACK_OFB64: return "CKM_SKIPJACK_OFB64";
		case CKM_SKIPJACK_CFB64: return "CKM_SKIPJACK_CFB64";
		case CKM_SKIPJACK_CFB32: return "CKM_SKIPJACK_CFB32";
		case CKM_SKIPJACK_CFB16: return "CKM_SKIPJACK_CFB16";
		case CKM_SKIPJACK_CFB8: return "CKM_SKIPJACK_CFB8";
		case CKM_SKIPJACK_WRAP: return "CKM_SKIPJACK_WRAP";
		case CKM_SKIPJACK_PRIVATE_WRAP: return "CKM_SKIPJACK_PRIVATE_WRAP";
		case CKM_SKIPJACK_RELAYX: return "CKM_SKIPJACK_RELAYX";
		case CKM_KEA_KEY_PAIR_GEN: return "CKM_KEA_KEY_PAIR_GEN";
		case CKM_KEA_KEY_DERIVE: return "CKM_KEA_KEY_DERIVE";
		case CKM_FORTEZZA_TIMESTAMP: return "CKM_FORTEZZA_TIMESTAMP";
		case CKM_BATON_KEY_GEN: return "CKM_BATON_KEY_GEN";
		case CKM_BATON_ECB128: return "CKM_BATON_ECB128";
		case CKM_BATON_ECB96: return "CKM_BATON_ECB96";
		case CKM_BATON_CBC128: return "CKM_BATON_CBC128";
		case CKM_BATON_COUNTER: return "CKM_BATON_COUNTER";
		case CKM_BATON_SHUFFLE: return "CKM_BATON_SHUFFLE";
		case CKM_BATON_WRAP: return "CKM_BATON_WRAP";
		case CKM_ECDSA_KEY_PAIR_GEN: return "CKM_ECDSA_KEY_PAIR_GEN";
//		case CKM_EC_KEY_PAIR_GEN: return "CKM_EC_KEY_PAIR_GEN";
		case CKM_ECDSA: return "CKM_ECDSA";
		case CKM_ECDSA_SHA1: return "CKM_ECDSA_SHA1";
		case CKM_ECDH1_DERIVE: return "CKM_ECDH1_DERIVE";
		case CKM_ECDH1_COFACTOR_DERIVE: return "CKM_ECDH1_COFACTOR_DERIVE";
		case CKM_ECMQV_DERIVE: return "CKM_ECMQV_DERIVE";
		case CKM_JUNIPER_KEY_GEN: return "CKM_JUNIPER_KEY_GEN";
		case CKM_JUNIPER_ECB128: return "CKM_JUNIPER_ECB128";
		case CKM_JUNIPER_CBC128: return "CKM_JUNIPER_CBC128";
		case CKM_JUNIPER_COUNTER: return "CKM_JUNIPER_COUNTER";
		case CKM_JUNIPER_SHUFFLE: return "CKM_JUNIPER_SHUFFLE";
		case CKM_JUNIPER_WRAP: return "CKM_JUNIPER_WRAP";
		case CKM_FASTHASH: return "CKM_FASTHASH";
		case CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN";
		case CKM_AES_ECB: return "CKM_AES_ECB";
		case CKM_AES_CBC: return "CKM_AES_CBC";
		case CKM_AES_MAC: return "CKM_AES_MAC";
		case CKM_AES_MAC_GENERAL: return "CKM_AES_MAC_GENERAL";
		case CKM_AES_CBC_PAD: return "CKM_AES_CBC_PAD";
/*OS
		case CKM_BLOWFISH_KEY_GEN: return "CKM_BLOWFISH_KEY_GEN";
		case CKM_BLOWFISH_CBC: return "CKM_BLOWFISH_CBC";
		case CKM_TWOFISH_KEY_GEN: return "CKM_TWOFISH_KEY_GEN";
		case CKM_TWOFISH_CBC: return "CKM_TWOFISH_CBC";
		case CKM_DES_ECB_ENCRYPT_DATA: return "CKM_DES_ECB_ENCRYPT_DATA";
		case CKM_DES_CBC_ENCRYPT_DATA: return "CKM_DES_CBC_ENCRYPT_DATA";
		case CKM_DES3_ECB_ENCRYPT_DATA: return "CKM_DES3_ECB_ENCRYPT_DATA";
		case CKM_DES3_CBC_ENCRYPT_DATA: return "CKM_DES3_CBC_ENCRYPT_DATA";
		case CKM_AES_ECB_ENCRYPT_DATA: return "CKM_AES_ECB_ENCRYPT_DATA";
		case CKM_AES_CBC_ENCRYPT_DATA: return "CKM_AES_CBC_ENCRYPT_DATA";
		case CKM_DSA_PARAMETER_GEN: return "CKM_DSA_PARAMETER_GEN";
*/
		case CKM_DH_PKCS_PARAMETER_GEN: return "CKM_DH_PKCS_PARAMETER_GEN";
		case CKM_X9_42_DH_PARAMETER_GEN: return "CKM_X9_42_DH_PARAMETER_GEN";
		case CKM_VENDOR_DEFINED: return "CKM_VENDOR_DEFINED";
		default:
			{
				char szError[1024];
				sprintf (szError, "Unknown CK_MECHANISM_TYPE %08lx", t);
				return szError;
			}
	}
}

static
std::string
Resolve_CK_RV (
	IN const CK_RV rv
) {
	switch (rv) {
		case CKR_OK: return "CKR_OK";
		case CKR_CANCEL: return "CKR_CANCEL";
		case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT: return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
		case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
		case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
		case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
		case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
		case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
		case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
		case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
		case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
		default:
			{
				char szError[1024];
				sprintf (szError, "PKCS#11 Error %08lx", rv);
				return szError;
			}
	}
}

static
std::string
Resolve_CK_FLAGS (
	IN const CK_FLAGS f
) {
	std::string r;

	if ((f&CKF_RNG)!=0) {
		r += "CKF_RNG,";
	}
	if ((f&CKF_WRITE_PROTECTED)!=0) {
		r += "CKF_WRITE_PROTECTED,";
	}
	if ((f&CKF_LOGIN_REQUIRED)!=0) {
		r += "CKF_LOGIN_REQUIRED,";
	}
	if ((f&CKF_USER_PIN_INITIALIZED)!=0) {
		r += "CKF_USER_PIN_INITIALIZED,";
	}
	if ((f&CKF_RESTORE_KEY_NOT_NEEDED)!=0) {
		r += "CKF_RESTORE_KEY_NOT_NEEDED,";
	}
	if ((f&CKF_CLOCK_ON_TOKEN)!=0) {
		r += "CKF_CLOCK_ON_TOKEN,";
	}
	if ((f&CKF_PROTECTED_AUTHENTICATION_PATH)!=0) {
		r += "CKF_PROTECTED_AUTHENTICATION_PATH,";
	}
	if ((f&CKF_DUAL_CRYPTO_OPERATIONS)!=0) {
		r += "CKF_DUAL_CRYPTO_OPERATIONS,";
	}
	if ((f&CKF_TOKEN_INITIALIZED)!=0) {
		r += "CKF_TOKEN_INITIALIZED,";
	}
	if ((f&CKF_SECONDARY_AUTHENTICATION)!=0) {
		r += "CKF_SECONDARY_AUTHENTICATION,";
	}
	if ((f&CKF_USER_PIN_COUNT_LOW)!=0) {
		r += "CKF_USER_PIN_COUNT_LOW,";
	}
	if ((f&CKF_USER_PIN_FINAL_TRY)!=0) {
		r += "CKF_USER_PIN_FINAL_TRY,";
	}
	if ((f&CKF_USER_PIN_LOCKED)!=0) {
		r += "CKF_USER_PIN_LOCKED,";
	}
	if ((f&CKF_USER_PIN_TO_BE_CHANGED)!=0) {
		r += "CKF_USER_PIN_TO_BE_CHANGED,";
	}
	if ((f&CKF_SO_PIN_COUNT_LOW)!=0) {
		r += "CKF_SO_PIN_COUNT_LOW,";
	}
	if ((f&CKF_SO_PIN_FINAL_TRY)!=0) {
		r += "CKF_SO_PIN_FINAL_TRY,";
	}
	if ((f&CKF_SO_PIN_LOCKED)!=0) {
		r += "CKF_SO_PIN_LOCKED,";
	}
	if ((f&CKF_SO_PIN_TO_BE_CHANGED)!=0) {
		r += "CKF_SO_PIN_TO_BE_CHANGED,";
	}

	if (r!="") {
		r.erase (r.length ()-1);
	}
	return r;
}

static
std::string
Resolve_CK_CERTIFICATE_TYPE (
	IN const CK_CERTIFICATE_TYPE t
) {
	switch (t) {
		case CKC_X_509: return "CKC_X_509";
		case CKC_X_509_ATTR_CERT: return "CKC_X_509_ATTR_CERT";
		case CKC_WTLS: return "CKC_WTLS";
		case CKC_VENDOR_DEFINED: return "CKC_VENDOR_DEFINED";
		default:
			{
				char szError[1024];
				sprintf (szError, "Unknown CK_CERTIFICATE_TYPE %08lx", t);
				return szError;
			}
	}
}

static
std::string
Resolve_CK_HW_FEATURE_TYPE (
	IN const CK_HW_FEATURE_TYPE t
) {
	switch (t) {
		case CKH_MONOTONIC_COUNTER: return "CKH_MONOTONIC_COUNTER";
		case CKH_CLOCK: return "CKH_CLOCK";
		case CKH_USER_INTERFACE: return "CKH_USER_INTERFACE";
		case CKH_VENDOR_DEFINED: return "CKH_VENDOR_DEFINED";
		default:
			{
				char szError[1024];
				sprintf (szError, "Unknown CK_HW_FEATURE_TYPE %08lx", t);
				return szError;
			}
	}
}

static
std::string
ParseSubject (
	IN const void * const p,
	IN const unsigned s
) {
	char szSubject[1024];
	bool fOK = false;

#if defined(_WIN32)
	CRYPT_DER_BLOB blobSubject = {s, (PBYTE)p};

	if (
		CertNameToStrA (
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			&blobSubject,
			CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
			szSubject,
			sizeof (szSubject)
		) != 0
	) {
		fOK = true;
	}
#else
	X509_NAME *name;
	name = X509_NAME_new ();
	if (name != NULL) {
		pkcs11_openssl_d2i_t pp = (pkcs11_openssl_d2i_t)p;
		if (
			d2i_X509_NAME (
				&name,
				&pp,
				s
			)
		) {
			X509_NAME_oneline (
				name,
				szSubject,
				sizeof (szSubject)
			);
			fOK = true;
		}
		X509_NAME_free (name);
	}
#endif
	if (fOK) {
		return szSubject;
	}
	else {
		return "ERROR";
	}
}

static
std::string
FixedStringToString (
	IN const void * const p,
	IN const unsigned s
) {
	std::string r;
	for (unsigned long k=0;k<s;k++) {
		unsigned char c = ((unsigned char *)p)[k];
		if (isprint (c)) {
			r+=c;
		}
		else {
			char x[10];
			sprintf (x, "\\x%02x", c & 0xff);
			r+=x;
		}
	}

	return r;
}

static
std::string
DumpToString (
	IN const void * const p,
	IN const unsigned s
) {
	std::string r;
	for (unsigned long k=0;k<s;k++) {
		if ((k%16)==0) {
			r+="\n";
		}
		unsigned char c = ((unsigned char *)p)[k];
		char x[10];
		sprintf (x, "%02x ", c & 0xff);
		r+=x;
	}
	r+="\n";

	return r;
}

static
void
Load (
	IN const std::string &strModule,
	OUT PKCS11_MODULE_HANDLE &hPKCS11,
	OUT CK_FUNCTION_LIST_PTR &pkcs11
) {
	CK_RV rv;

#if defined(_WIN32)
	hPKCS11 = LoadLibraryA (strModule.c_str ());
#else
	hPKCS11 = dlopen (strModule.c_str (), RTLD_NOW);
#endif

	if (hPKCS11 == NULL) {
		throw CEGeneral ("Cannot load module");
	}

	CK_C_GetFunctionList C_GetFunctionList = NULL;
#if defined(_WIN32)
	C_GetFunctionList = (CK_C_GetFunctionList) (
		GetProcAddress (hPKCS11, "C_GetFunctionList")
	);
#else
	void *p = dlsym (
		hPKCS11,
		"C_GetFunctionList"
	);

	memmove (
		&C_GetFunctionList,
		&p,
		sizeof (void *)
	);
#endif

	if (C_GetFunctionList == NULL) {
		throw CEGeneral ("Cannot get function list entry");
	}

	if ((rv = C_GetFunctionList (&pkcs11)) != CKR_OK) {
		throw CEPKCS11 ("Cannot get function list", rv);
	}

	if ((rv = pkcs11->C_Initialize (NULL)) != CKR_OK) {
		throw CEPKCS11 ("Cannot initialize", rv);
	}
}

static
void
Unload (
	IN OUT PKCS11_MODULE_HANDLE &hPKCS11,
	IN OUT CK_FUNCTION_LIST_PTR &pkcs11
) {
	if (pkcs11 != NULL) {
		pkcs11->C_Finalize (NULL);
		pkcs11 = NULL;
	}

	if (hPKCS11 != NULL) {
#if defined(_WIN32)
		FreeLibrary (hPKCS11);
#else
		dlclose (hPKCS11);
#endif
		hPKCS11 = NULL;
	}
}

static
void
Info (
	IN const CK_FUNCTION_LIST_PTR &pkcs11
) {
	CK_RV rv;
	CK_INFO info;

	if (
		(rv = pkcs11->C_GetInfo (
			&info
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_GetInfo", rv);
	}

	printf (
		(
			"Provider Information:\n"
			"%30s: %u.%u\n"
			"%30s: %s\n"
			"%30s: %08lx\n"
		),
		"cryptokiVersion", info.cryptokiVersion.major, info.cryptokiVersion.minor,
		"manufacturerID", FixedStringToString (info.manufacturerID, sizeof (info.manufacturerID)).c_str (),
		"flags", info.flags
	);

	if (info.cryptokiVersion.major >= 2) {
		printf (
			(
				"%30s: %u.%u\n"
				"%30s: %s\n"
			),
			"libraryVersion", info.libraryVersion.major, info.libraryVersion.minor,
			"libraryDescription", FixedStringToString (info.libraryDescription, sizeof (info.libraryDescription)).c_str ()
		);
	}
}

static
void
SlotList (
	IN const CK_FUNCTION_LIST_PTR &pkcs11
) {
	CK_RV rv;
	CK_SLOT_ID slots[1024];
	CK_ULONG slotsnum;

	if (
		(rv = pkcs11->C_GetSlotList (
			FALSE,
			NULL,
			&slotsnum
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_GetSlotList", rv);
	}

	if (slotsnum >= sizeof(slots)/sizeof(slots[0])) {
		throw CEPKCS11 ("C_GetSlotList", CKR_BUFFER_TOO_SMALL);
	}

	if (
		(rv = pkcs11->C_GetSlotList (
			FALSE,
			slots,
			&slotsnum
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_GetSlotList", rv);
	}

	if (slotsnum == 0) {
		printf ("No slot found\n");
	}

	for (CK_SLOT_ID slot=0;slot<slotsnum && slot < sizeof (slots)/sizeof (CK_SLOT_ID);slot++) {
		CK_SLOT_INFO info;

		if (
			(rv = pkcs11->C_GetSlotInfo (
				slots[slot],
				&info
			)) == CKR_OK
		) {
			printf ("%lu\t%s\n", slots[slot], FixedStringToString (info.slotDescription, sizeof (info.slotDescription)).c_str ());
		}
		else {
			printf ("C_GetSlotInfo failed %08lx\n", rv);
		}
	}
}

static
void
Dump (
	IN const CK_FUNCTION_LIST_PTR &pkcs11,
	IN const CK_SLOT_ID slotSlot,
	IN const std::string &strPIN
) {
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE objects[1024];
	CK_ULONG objectsmax = sizeof (objects) / sizeof (CK_OBJECT_HANDLE);
	CK_ULONG objectssize;
	CK_ULONG i;
	CK_SLOT_ID slots[1024];
	CK_ULONG slotsnum;

	if (
		(rv = pkcs11->C_GetSlotList (
			FALSE,
			NULL,
			&slotsnum
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_GetSlotList", rv);
	}

	if (slotsnum >= sizeof(slots)/sizeof(slots[0])) {
		throw CEPKCS11 ("C_GetSlotList", CKR_BUFFER_TOO_SMALL);
	}

	if (
		(rv = pkcs11->C_GetSlotList (
			FALSE,
			slots,
			&slotsnum
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_GetSlotList", rv);
	}

	if (
		(rv=pkcs11->C_OpenSession (
			slotSlot,
			CKF_SERIAL_SESSION,
			NULL_PTR,
			NULL_PTR,
			&hSession
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_OpenSession", rv);
	}

	CK_TOKEN_INFO info;

	if (
		(rv = pkcs11->C_GetTokenInfo (
			slotSlot,
			&info
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_GetTokenInfo", rv);
	}

	printf (
		(
			"Token Information:\n"
			"%30s: %s\n"
			"%30s: %s\n"
			"%30s: %s\n"
			"%30s: %s\n"
			"%30s: %s\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %ld\n"
			"%30s: %03d.%03d\n"
			"%30s: %03d.%03d\n"
			"%30s: %s\n"
		),
		"label", FixedStringToString (info.label, sizeof (info.label)).c_str (),
		"manufacturerID", FixedStringToString (info.manufacturerID, sizeof (info.manufacturerID)).c_str (),
		"model", FixedStringToString (info.model, sizeof (info.model)).c_str (),
		"serialNumber", FixedStringToString (info.serialNumber, sizeof (info.serialNumber)).c_str (),
		"flags", Resolve_CK_FLAGS (info.flags).c_str (),
		"ulMaxSessionCount", info.ulMaxSessionCount,
		"ulMaxSessionCount", info.ulMaxSessionCount,
		"ulMaxPinLen", info.ulMaxPinLen,
		"ulMinPinLen", info.ulMinPinLen,
		"ulTotalPublicMemory", info.ulTotalPublicMemory,
		"ulFreePublicMemory", info.ulFreePublicMemory,
		"ulTotalPrivateMemory", info.ulTotalPrivateMemory,
		"ulFreePrivateMemory", info.ulFreePrivateMemory,
		"hardwareVersion", info.hardwareVersion.major, info.hardwareVersion.minor,
		"firmwareVersion", info.firmwareVersion.major, info.firmwareVersion.minor,
		"utcTime", FixedStringToString (info.utcTime, sizeof (info.utcTime)).c_str ()
	);

	if (
		(rv=pkcs11->C_Login (
			hSession,
			CKU_USER,
			(CK_CHAR_PTR)strPIN.c_str (),
			(CK_ULONG)strPIN.length ()
		)) != CKR_OK &&
		rv != CKR_USER_ALREADY_LOGGED_IN
	) {
		throw CEPKCS11 ("C_Login", rv);
	}

	if (
		(rv=pkcs11->C_FindObjectsInit (
			hSession,
			NULL_PTR,
			0
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_FindObjectsInit", rv);
	}

	if (
		(rv=pkcs11->C_FindObjects (
			hSession,
			objects,
			objectsmax,
			&objectssize
		)) != CKR_OK
	) {
		throw CEPKCS11 ("C_FindObjects", rv);
	}

	for (i=0;i<objectssize;i++) {

		printf ("Object %lu\n", i);

		CK_ULONG lObjectSize;
		if (
			(rv=pkcs11->C_GetObjectSize (
				hSession,
				objects[i],
				&lObjectSize
			)) != CKR_OK
		) {
			printf ("%30s: Unknown\n", "Object size");
		}
		else {
			printf ("%30s: %ld\n", "Object size", lObjectSize);
		}

		for (int j=0;attrdescAttributes[j].nId!=-1;j++) {
			char Buffer[10*1024];
			CK_ATTRIBUTE t[] = {
				{(CK_ATTRIBUTE_TYPE)attrdescAttributes[j].nId, Buffer, sizeof (Buffer)}
			};

			if (
				(rv=pkcs11->C_GetAttributeValue (
					hSession,
					objects[i],
					t,
					sizeof (t) / sizeof (CK_ATTRIBUTE)
				)) == CKR_OK
			) {
				printf ("%30s: ", attrdescAttributes[j].szName);

				switch (attrdescAttributes[j].attrtypeType) {
					case attrtypeUnknown:
						printf ("Unknown value type");
					break;
					case attrtypeString:
					case attrtypeCK_CHAR:
					case attrtypeCK_DATE:
						printf ("%s", FixedStringToString (t[0].pValue, t[0].ulValueLen).c_str ());
					break;
					case attrtypeBigInteger:
					case attrtypeByteArray:
						printf ("%s", DumpToString (t[0].pValue, t[0].ulValueLen).c_str ());
					break;
					break;
					case attrtypeSubject:
					case attrtypeSubject1:
						printf ("%s\n", ParseSubject (t[0].pValue, t[0].ulValueLen).c_str ());
					break;
					case attrtypeCK_BBOOL:
						{
							CK_BBOOL b = *(CK_BBOOL *)t[0].pValue;
							if (b != CK_FALSE) {
								printf ("TRUE");
							}
							else {
								printf ("FALSE");
							}
						}
					break;
					case attrtypeCK_ULONG:
						{
							CK_ULONG l = *(CK_ULONG *)t[0].pValue;
							printf ("%ld", l);
						}
					break;
					case attrtypeCK_CERTIFICATE_TYPE:
						printf ("%s", Resolve_CK_CERTIFICATE_TYPE (*(CK_CERTIFICATE_TYPE *)t[0].pValue).c_str ());
					break;
					case attrtypeCK_KEY_TYPE:
						printf ("%s", Resolve_CK_KEY_TYPE (*(CK_KEY_TYPE *)t[0].pValue).c_str ());
					break;
					case attrtypeCK_MECHANISM_TYPE:
						printf ("%s", Resolve_CK_MECHANISM_TYPE (*(CK_MECHANISM_TYPE *)t[0].pValue).c_str ());
					break;
					case attrtypeCK_OBJECT_CLASS:
						printf ("%s", Resolve_CK_OBJECT_CLASS (*(CK_OBJECT_CLASS *)t[0].pValue).c_str ());
					break;
					case attrtypeCK_HW_FEATURE_TYPE:
						printf ("%s", Resolve_CK_HW_FEATURE_TYPE (*(CK_HW_FEATURE_TYPE *)t[0].pValue).c_str ());
					break;
					case attrtypeCK_ATTRIBUTE_PTR:
						printf ("Exists but value not parsed");
					break;
					case attrtypeCK_MECHANISM_TYPE_PTR:
						printf ("Exists but value not parsed");
					break;
					default:
						printf ("Unknown type");
					break;
				}

				printf ("\n");
			}
		}
	}

	pkcs11->C_FindObjectsFinal (hSession);
	pkcs11->C_Logout (hSession);
	pkcs11->C_CloseSession (hSession);
}

std::string
GetPIN (
	IN const std::string &strPIN
) {
	std::string strR;

	if (strPIN != "-") {
		strR = strPIN;
	}
	else {
#if defined(_WIN32)
		char c;

		fprintf (stderr, "Please enter PIN: ");

		while ((c = getch ()) != '\r') {
			fputc ('*', stderr);
			strR += c;
		}

		fprintf (stderr, "\n");
#else
		strR = getpass ("Please enter PIN: ");
#endif
	}

	return strR;
}


int
main (
	const int argc,
	const char * const argv[]
) {

	fprintf (
		stderr,
		(
			"%s %s - PKI Cryptoki token dump\n"
			"Written by Alon Bar-Lev\n"
			"\n"
			"Copyright (C) 2005-2006 Alon Bar-Lev.\n"
			"This is free software; see the source for copying conditions.\n"
			"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
			"\n"
		),
		PACKAGE_NAME,
		PACKAGE_VERSION
	);

	bool fUsageOK = false;
	bool fOK = false;

	if (argc > 1) {
		std::string strCommand = argv[1];

		if (strCommand == "info") {
			if (argc == 3) {
				std::string strModule = argv[2];
				fUsageOK = true;

				PKCS11_MODULE_HANDLE hPKCS11 = NULL;
				CK_FUNCTION_LIST_PTR pkcs11 = NULL;
				try {
					Load (strModule, hPKCS11, pkcs11);
					Info (pkcs11);

					fOK = true;
				}
				catch (const CEPKCS11 &e) {
					fprintf (stderr, "Fatal: %s-%s\n", e.m_str.c_str (), Resolve_CK_RV (e.m_rv).c_str ());
				}
				catch (const CEGeneral &e) {
					fprintf (stderr, "Fatal: %s\n", e.m_str.c_str ());
				}
				catch (...) {
					fprintf (stderr, "Unknown error\n");
				}
				Unload (hPKCS11, pkcs11);
			}
		}
		else if (strCommand == "slotlist") {
			if (argc == 3) {
				std::string strModule = argv[2];
				fUsageOK = true;

				PKCS11_MODULE_HANDLE hPKCS11 = NULL;
				CK_FUNCTION_LIST_PTR pkcs11 = NULL;
				try {
					Load (strModule, hPKCS11, pkcs11);
//while (1) {
					SlotList (pkcs11);
//sleep (1);
//}

					fOK = true;
				}
				catch (const CEPKCS11 &e) {
					fprintf (stderr, "Fatal: %s-%s\n", e.m_str.c_str (), Resolve_CK_RV (e.m_rv).c_str ());
				}
				catch (const CEGeneral &e) {
					fprintf (stderr, "Fatal: %s\n", e.m_str.c_str ());
				}
				catch (...) {
					fprintf (stderr, "Unknown error\n");
				}
				Unload (hPKCS11, pkcs11);
			}
		}
		else if (strCommand == "dump") {
			if (argc == 5) {
				std::string strModule = argv[2];
				CK_SLOT_ID slotSlot = strtoul(argv[3], NULL, 0);
				std::string strPIN = GetPIN (argv[4]);
				fUsageOK = true;

				PKCS11_MODULE_HANDLE hPKCS11 = NULL;
				CK_FUNCTION_LIST_PTR pkcs11 = NULL;
				try {
					Load (strModule, hPKCS11, pkcs11);
					Dump (pkcs11, slotSlot, strPIN);

					fOK = true;
				}
				catch (const CEPKCS11 &e) {
					fprintf (stderr, "Fatal: %s-%s\n", e.m_str.c_str (), Resolve_CK_RV (e.m_rv).c_str ());
				}
				catch (const CEGeneral &e) {
					fprintf (stderr, "Fatal: %s\n", e.m_str.c_str ());
				}
				catch (...) {
					fprintf (stderr, "Unknown error\n");
				}
				Unload (hPKCS11, pkcs11);
			}
		}
	}

	if (!fUsageOK) {
		std::string strModule = argv[0];
		size_t n = strModule.find_last_of ('\\');
		if (n != std::string::npos) {
			strModule = strModule.substr (n+1);
		}

		fprintf (
			stderr,
			(
				"Usage:\n"
				"%s info module\n"
				"%s slotlist module\n"
				"%s dump module slot user_pin|-\n"
			),
			strModule.c_str (),
			strModule.c_str (),
			strModule.c_str ()
		);
		fOK = false;
	}

	if (fOK) {
		exit (0);
	}
	else {
		exit (1);
	}

	return 1;
}
