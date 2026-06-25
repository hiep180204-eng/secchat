#ifndef SECCHAT_INFRA_CRYPTO_H
#define SECCHAT_INFRA_CRYPTO_H

/* Compute hex-encoded SHA-256 of `in`. `out` must be at least 65 bytes. */
void sha256_hex(const char *in, char out[65]);

/* Compute Base64-encoded SHA-1 of `in` (for WebSocket accept key).
   `out` must be at least 29 bytes. */
void sha1_b64(const char *in, char out[29]);

/* ── PBKDF2 password hashing ─────────────────────────────── */

/* PBKDF2-HMAC-SHA256.
   Returns 1 on success, 0 on failure. */
int pbkdf2_sha256(const char *password,
                  const unsigned char *salt, int salt_len,
                  int iterations,
                  unsigned char *out, int out_len);

/* Fill `buf` with `len` cryptographic random bytes (OpenSSL RAND).
   Returns 1 on success, 0 on failure. */
int crypto_random_bytes(unsigned char *buf, int len);

/* Hex-encode `len` bytes from `in` into `out`.
   `out` must be at least len*2+1 bytes. */
void hex_encode(const unsigned char *in, int len, char *out);

/* Hex-decode `hex` string into `out`.
   Returns decoded byte count, or -1 on error. */
int hex_decode(const char *hex, unsigned char *out, int max_out);

#endif /* SECCHAT_INFRA_CRYPTO_H */
