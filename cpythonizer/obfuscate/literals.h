/*
 * literals.h - build-time string encryption for the loader.
 *
 * CPY_HSTR("x") / CPY_HWSTR("x") are placeholders: cpythonizer rewrites them
 * into XOR-encrypted byte arrays that are decoded at the call site, so the
 * plaintext never reaches the binary. Without the guard they expand to the
 * plain literals.
 *
 * WHY THE POOL
 * ------------
 * The obvious shape -
 *
 *     f(obfh_decrypt_str((unsigned char[]){...}, key, len))
 *
 * i.e. decrypting a compound literal *in place* and handing the pointer on -
 * does not work on MSVC. Measured on VS2022 17.x, /O2 /MT:
 *
 *     compound literal + in-place decode  ->  wrong string (GetEnvironmentVariableW
 *                                            returns 0 for a variable that exists)
 *     static bytes     + decode into out ->  correct
 *     compound literal + decode into out ->  correct
 *
 * The temporary behind the literal is not dependable once a noinline helper
 * has written through the pointer, so the decoded value is written into
 * per-thread static storage instead and stays valid for POOL_SLOTS further
 * decodes. Every call site in the loader decodes at most a couple of strings
 * before consuming them, so the pool never wraps in practice.
 *
 * Split out of obfus_msvc.h because resolve.h needs the placeholders too and
 * must be included before the hidden-import macros exist.
 */
#ifndef OBFH_LITERALS_H
#define OBFH_LITERALS_H

#include <stddef.h>

/* CPY_HSTR / CPY_HWSTR are defined by whoever includes this first. */

#define OBFH_POOL_SLOTS 16u
#define OBFH_POOL_LEN 64u

static __declspec(thread) unsigned char obfh_pool_n[OBFH_POOL_SLOTS][OBFH_POOL_LEN];
static __declspec(thread) wchar_t obfh_pool_w[OBFH_POOL_SLOTS][OBFH_POOL_LEN];
static __declspec(thread) unsigned obfh_pool_next;

__declspec(noinline) static const char *obfh_str_pool(const unsigned char *enc,
                                                     unsigned char key, size_t len)
{
    unsigned char *out;
    size_t i;

    if (len > OBFH_POOL_LEN)
        len = OBFH_POOL_LEN;
    out = obfh_pool_n[obfh_pool_next++ % OBFH_POOL_SLOTS];
    for (i = 0; i < len; i++)
        out[i] = (unsigned char)(enc[i] ^ key);
    return (const char *)out;
}

/*
 * `enc` holds little-endian UTF-16 code units, one byte per element. Both
 * bytes are XORed with the key, so the decoder must XOR the whole code unit.
 */
__declspec(noinline) static const wchar_t *obfh_wstr_pool(const unsigned char *enc,
                                                          unsigned char key,
                                                          size_t bytes)
{
    wchar_t *out;
    size_t i;

    out = obfh_pool_w[obfh_pool_next++ % OBFH_POOL_SLOTS];
    for (i = 0; i < bytes / 2 && i + 1 < OBFH_POOL_LEN; i++)
        out[i] = (wchar_t)((enc[i * 2] ^ key) | ((enc[i * 2 + 1] ^ key) << 8));
    out[bytes / 2 < OBFH_POOL_LEN ? bytes / 2 : OBFH_POOL_LEN - 1] = 0;
    return out;
}

/*
 * Decode a *static const* blob into caller-owned storage. Use this when the
 * decoded string must stay valid across statements (the module list the
 * resolver walks does).
 */
__declspec(noinline) static wchar_t *obfh_wstr_from_static(wchar_t *out, size_t cap,
                                                          const unsigned char *enc,
                                                          unsigned char key,
                                                          size_t bytes)
{
    size_t i;

    for (i = 0; i < bytes / 2 && i + 1 < cap; i++)
        out[i] = (wchar_t)((enc[i * 2] ^ key) | ((enc[i * 2 + 1] ^ key) << 8));
    out[i] = 0;
    return out;
}

#endif /* OBFH_LITERALS_H */