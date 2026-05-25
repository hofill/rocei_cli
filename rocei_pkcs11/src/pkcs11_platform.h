#pragma once

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) __attribute__((visibility("default"))) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

/* ── Platform: PC/SC + SHA ─────────────────────────────────────────────── */
#ifdef __APPLE__
#  include <PCSC/winscard.h>
#  include <PCSC/wintypes.h>
#  include <CommonCrypto/CommonDigest.h>
#elif defined(_WIN32)
#  include <winscard.h>
#  include <openssl/sha.h>
#  define CC_SHA1_DIGEST_LENGTH   SHA_DIGEST_LENGTH
#  define CC_SHA224_DIGEST_LENGTH SHA224_DIGEST_LENGTH
#  define CC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#  define CC_SHA384_DIGEST_LENGTH SHA384_DIGEST_LENGTH
#  define CC_SHA512_DIGEST_LENGTH SHA512_DIGEST_LENGTH
#  define CC_LONG size_t
static inline unsigned char *CC_SHA1(const void *d, CC_LONG n, unsigned char *md)   { return SHA1(d, n, md); }
static inline unsigned char *CC_SHA224(const void *d, CC_LONG n, unsigned char *md) { return SHA224(d, n, md); }
static inline unsigned char *CC_SHA256(const void *d, CC_LONG n, unsigned char *md) { return SHA256(d, n, md); }
static inline unsigned char *CC_SHA384(const void *d, CC_LONG n, unsigned char *md) { return SHA384(d, n, md); }
static inline unsigned char *CC_SHA512(const void *d, CC_LONG n, unsigned char *md) { return SHA512(d, n, md); }
#  ifndef strcasecmp
#    define strcasecmp _stricmp
#  endif
#else
/* Linux / pcsclite */
#  include <PCSC/winscard.h>
#  include <PCSC/wintypes.h>
#  include <openssl/sha.h>
/* pcsclite omits the _A typedef variants that Windows/macOS define */
#  define SCARD_READERSTATE_A SCARD_READERSTATE
#  define CC_SHA1_DIGEST_LENGTH   SHA_DIGEST_LENGTH
#  define CC_SHA224_DIGEST_LENGTH SHA224_DIGEST_LENGTH
#  define CC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#  define CC_SHA384_DIGEST_LENGTH SHA384_DIGEST_LENGTH
#  define CC_SHA512_DIGEST_LENGTH SHA512_DIGEST_LENGTH
#  define CC_LONG size_t
static inline unsigned char *CC_SHA1(const void *d, CC_LONG n, unsigned char *md)   { return SHA1(d, n, md); }
static inline unsigned char *CC_SHA224(const void *d, CC_LONG n, unsigned char *md) { return SHA224(d, n, md); }
static inline unsigned char *CC_SHA256(const void *d, CC_LONG n, unsigned char *md) { return SHA256(d, n, md); }
static inline unsigned char *CC_SHA384(const void *d, CC_LONG n, unsigned char *md) { return SHA384(d, n, md); }
static inline unsigned char *CC_SHA512(const void *d, CC_LONG n, unsigned char *md) { return SHA512(d, n, md); }
#endif
