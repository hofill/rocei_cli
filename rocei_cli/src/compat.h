#pragma once

/* SHA-256: CommonCrypto on Apple, OpenSSL everywhere else */
#ifdef __APPLE__
#  include <CommonCrypto/CommonDigest.h>
#else
#  include <openssl/sha.h>
#  define CC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#  define CC_LONG                 size_t
static inline unsigned char *CC_SHA256(const void *d, CC_LONG n, unsigned char *md) {
    return SHA256(d, n, md);
}
#endif

/* POSIX helpers */
#ifndef _WIN32
#  include <unistd.h>
/* POSIX execvp takes char *const * — wrap to accept const char *const * */
#  define rocei_execvp(prog, args) execvp((prog), (char *const *)(args))
#else
#  include <io.h>
#  include <process.h>
#  define access  _access
#  define R_OK    4
/* MinGW _execvp already takes const char *const * */
#  define rocei_execvp(prog, args) _execvp((prog), (const char *const *)(args))
/* getpass: MinGW doesn't provide it; read from stdin without echo */
#  include <conio.h>
static inline char *getpass(const char *prompt) {
    static char buf[64];
    fprintf(stderr, "%s", prompt);
    int i = 0, c;
    while ((c = _getch()) != '\r' && c != '\n' && i < 63) buf[i++] = (char)c;
    buf[i] = '\0';
    fputc('\n', stderr);
    return buf;
}
#endif
