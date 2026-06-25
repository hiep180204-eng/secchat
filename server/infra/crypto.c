/*
 * infra/crypto.c — các tiện ích mật mã cấp thấp của server (qua OpenSSL).
 *
 * Gồm: băm SHA-256/SHA-1, PBKDF2 (dùng cho lớp băm mật khẩu 600k vòng phía
 * server), sinh byte ngẫu nhiên an toàn và mã hóa/giải mã hex. Đây KHÔNG phải
 * mã hóa nội dung tin nhắn — server không bao giờ thấy plaintext.
 */
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"

/* SHA-256 của chuỗi `in`, ghi ra hex 64 ký tự + NUL (rỗng nếu lỗi). */
void sha256_hex(const char *in, char out[65])
{
    unsigned char digest[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || !in ||
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, in, strlen(in)) != 1 ||
            EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        out[0] = '\0';
        return;
    }
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
}

/* SHA-1 rồi base64 — dùng cho header Sec-WebSocket-Accept khi bắt tay WebSocket. */
void sha1_b64(const char *in, char out[29])
{
    unsigned char d[20];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || !in ||
            EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, in, strlen(in)) != 1 ||
            EVP_DigestFinal_ex(ctx, d, NULL) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        out[0] = '\0';
        return;
    }
    EVP_MD_CTX_free(ctx);

    static const char *T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int j = 0;
    for (int i = 0; i < 20; i += 3) {
        int r = (20 - i >= 3) ? 3 : (20 - i);
        unsigned char a = d[i];
        unsigned char b = (r > 1) ? d[i + 1] : 0;
        unsigned char c = (r > 2) ? d[i + 2] : 0;
        out[j++] = T[a >> 2];
        out[j++] = T[((a & 3) << 4) | (b >> 4)];
        out[j++] = (r > 1) ? T[((b & 0xf) << 2) | (c >> 6)] : '=';
        out[j++] = (r > 2) ? T[c & 0x3f]                     : '=';
    }
    out[j] = '\0';
}

/* ── PBKDF2 ──────────────────────────────────────────────── */

/* PBKDF2-HMAC-SHA256: server băm lại password-hash của client với salt ngẫu
 * nhiên + nhiều vòng (lớp 600k) trước khi lưu, chống dò mật khẩu offline. */
int pbkdf2_sha256(const char *password,
                  const unsigned char *salt, int salt_len,
                  int iterations,
                  unsigned char *out, int out_len)
{
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                              salt, salt_len,
                              iterations,
                              EVP_sha256(),
                              out_len, out);
}

/* Sinh `len` byte ngẫu nhiên an toàn (salt, token...). Trả 1 nếu thành công. */
int crypto_random_bytes(unsigned char *buf, int len)
{
    return RAND_bytes(buf, len) == 1;
}

/* Mã hóa `len` byte thành chuỗi hex (out phải đủ len*2 + 1). */
void hex_encode(const unsigned char *in, int len, char *out)
{
    for (int i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", in[i]);
    out[len * 2] = '\0';
}

/* Giải hex thành bytes; trả về số byte, hoặc -1 nếu hex lỗi/vượt max_out. */
int hex_decode(const char *hex, unsigned char *out, int max_out)
{
    int slen = (int)strlen(hex);
    if (slen % 2 != 0) return -1;
    int bytes = slen / 2;
    if (bytes > max_out) return -1;
    for (int i = 0; i < bytes; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%2x", &val) != 1) return -1;
        out[i] = (unsigned char)val;
    }
    return bytes;
}
