/*
 * transport/ws.c — tầng WebSocket: bắt tay HTTP Upgrade, đọc/ghi frame.
 *
 * Giải mask frame client→server, đóng frame server→client, xử lý ping/pong và
 * frame phân mảnh. Payload bên trong frame là JSON command/response của ứng dụng.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#include <openssl/ssl.h>

#include "ws.h"
#include "crypto.h"
#include "metrics.h"

#define WS_GUID        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_MAX_HEADERS  64     /* S4: reject requests with > 64 headers */
#define WS_MAX_OVERSIZE_DRAIN (32u * 1024u * 1024u)

/* ── helper: read exactly `len` bytes from SSL ─────────────── */
static int ssl_read_full(SSL *ssl, void *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = SSL_read(ssl, (char *)buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

/* S4: Case-insensitive substring search for header token matching.
 * Used to find "Upgrade" inside "Connection: keep-alive, Upgrade". */
static int str_icontains(const char *hay, const char *needle)
{
    size_t nlen = strlen(needle);
    for (; *hay; hay++) {
        if (strncasecmp(hay, needle, nlen) == 0) return 1;
    }
    return 0;
}

/* S4: Hardened WebSocket handshake parser.
 *
 * Validates all RFC 6455 required headers rather than just searching for
 * the Sec-WebSocket-Key via strstr (which is vulnerable to key patterns
 * embedded in header values).
 *
 * Enforces:
 *   • GET method only
 *   • Upgrade: websocket          (case-insensitive, no duplicates)
 *   • Connection: Upgrade         (case-insensitive token, no duplicates)
 *   • Sec-WebSocket-Version: 13   (no duplicates)
 *   • Sec-WebSocket-Key present   (no duplicates)
 *   • Header count ≤ WS_MAX_HEADERS  (anti-slowloris)
 */
int ws_build_accept(const char *req, char *accept, size_t accept_len)
{
    if (!req || !accept || accept_len < 29) return 0;
    accept[0] = '\0';

    /* 1. Validate request line: "GET <path> HTTP/1.1" */
    if (strncmp(req, "GET ", 4) != 0) return 0;
    const char *rl_end = strstr(req, "\r\n");
    if (!rl_end) return 0;
    const char *http11 = " HTTP/1.1";
    size_t h11len = strlen(http11);
    size_t rl_len = (size_t)(rl_end - req);
    if (rl_len < h11len) return 0;
    if (memcmp(rl_end - h11len, http11, h11len) != 0) return 0;

    /* 2. Parse headers */
    const char *pos       = rl_end + 2;  /* skip initial CRLF */
    char ws_key[128]      = {0};
    int  seen_upgrade     = 0;           /* Upgrade: websocket */
    int  seen_conn        = 0;           /* Connection: Upgrade */
    int  seen_version     = 0;           /* Sec-WebSocket-Version: 13 */
    int  seen_key         = 0;           /* Sec-WebSocket-Key */
    int  hcount           = 0;

    while (*pos) {
        const char *nl = strstr(pos, "\r\n");
        if (!nl) break;
        if (nl == pos) break;               /* blank line = end of headers */

        if (++hcount > WS_MAX_HEADERS) return 0;

        /* Split at first ':' */
        const char *colon = (const char *)memchr(pos, ':', (size_t)(nl - pos));
        if (!colon) { pos = nl + 2; continue; }

        size_t name_len = (size_t)(colon - pos);
        if (name_len == 0 || name_len > 63) { pos = nl + 2; continue; }
        char name[64] = {0};
        memcpy(name, pos, name_len);

        /* Trim value */
        const char *vs = colon + 1;
        while (*vs == ' ' || *vs == '\t') vs++;
        const char *ve = nl;
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
        size_t vlen = (size_t)(ve - vs);
        char val[256] = {0};
        if (vlen > 255) vlen = 255;
        memcpy(val, vs, vlen);

        if (strcasecmp(name, "Upgrade") == 0) {
            if (seen_upgrade++) return 0;           /* duplicate */
            if (strcasecmp(val, "websocket") != 0) return 0;
        } else if (strcasecmp(name, "Connection") == 0) {
            if (seen_conn++) return 0;              /* duplicate */
            if (!str_icontains(val, "Upgrade")) return 0;
        } else if (strcasecmp(name, "Sec-WebSocket-Version") == 0) {
            if (seen_version++) return 0;           /* duplicate */
            if (strcmp(val, "13") != 0) return 0;
        } else if (strcasecmp(name, "Sec-WebSocket-Key") == 0) {
            if (seen_key++) return 0;               /* duplicate */
            if (vlen == 0 || vlen > 127) return 0;
            memcpy(ws_key, val, vlen);
        }

        pos = nl + 2;
    }

    /* 3. All required headers must be present */
    if (!seen_upgrade || !seen_conn || !seen_version || !seen_key)
        return 0;

    /* 4. Compute and send Sec-WebSocket-Accept */
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", ws_key, WS_GUID);
    sha1_b64(combined, accept);
    return 1;
}

int ws_handshake(SSL *ssl, const char *req)
{
    char accept[29];
    if (!ws_build_accept(req, accept, sizeof(accept))) return 0;

    char resp[512];
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept);
    return SSL_write(ssl, resp, (int)strlen(resp)) > 0;
}

int ws_decode_client_frame(const unsigned char *frame, size_t frame_len,
                           char *out, size_t maxlen, int *opcode_out)
{
    if (opcode_out) *opcode_out = -1;
    if (!frame || frame_len < 2) return -1;

    int    op     = frame[0] & 0x0f;
    int    fin    = (frame[0] & 0x80) != 0;
    int    rsv    = (frame[0] & 0x70) != 0;
    int    masked = (frame[1] & 0x80) != 0;
    size_t plen   = frame[1] & 0x7f;
    size_t off    = 2;

    if (opcode_out) *opcode_out = op;
    if (op == 0x08) return -1;
    if (!fin || rsv) return -1;
    if (op != 0x01 && op != 0x09 && op != 0x0a) return -1;

    if (plen == 126) {
        if (frame_len < off + 2) return -1;
        plen = ((size_t)frame[off] << 8) | (size_t)frame[off + 1];
        off += 2;
    } else if (plen == 127) {
        if (frame_len < off + 8) return -1;
        uint64_t wide = 0;
        for (int i = 0; i < 8; i++)
            wide = (wide << 8) | frame[off + (size_t)i];
        if (wide > (uint64_t)((size_t)-1)) return -1;
        plen = (size_t)wide;
        off += 8;
    }

    if ((op == 0x09 || op == 0x0a) && plen > 125) return -1;
    if (!masked) return -1;
    if (frame_len < off + 4) return -1;

    const unsigned char *mk = frame + off;
    off += 4;

    if (!out || maxlen == 0 || plen >= maxlen) return -2;
    if (frame_len < off || plen > frame_len - off) return -1;

    for (size_t i = 0; i < plen; i++)
        out[i] = (char)(frame[off + i] ^ mk[i & 3]);
    out[plen] = '\0';

    if (op == 0x09 || op == 0x0a) return 0;
    return (int)plen;
}

int ws_send(SSL *ssl, const char *data)
{
    size_t dlen = strlen(data);
    unsigned char hdr[10];
    int hlen = 0;
    hdr[hlen++] = 0x81;
    if (dlen <= 125) {
        hdr[hlen++] = (unsigned char)dlen;
    } else if (dlen <= 65535) {
        hdr[hlen++] = 126;
        hdr[hlen++] = (dlen >> 8) & 0xff;
        hdr[hlen++] = dlen & 0xff;
    } else {
        hdr[hlen++] = 127;
        for (int i = 7; i >= 0; i--)
            hdr[hlen++] = (dlen >> (i * 8)) & 0xff;
    }
    unsigned char *frame = (unsigned char *)malloc(hlen + dlen);
    if (!frame) return -1;
    memcpy(frame, hdr, hlen);
    memcpy(frame + hlen, data, dlen);
    int r = SSL_write(ssl, frame, (int)(hlen + dlen));
    free(frame);
    if (r > 0) metrics_ws_frame_sent(hlen + dlen);
    return r;
}

int ws_recv(SSL *ssl, char *out, int maxlen)
{
    uint64_t t0 = metrics_now_us();
    unsigned char h[2];
    if (ssl_read_full(ssl, h, 2) < 0) return -1;

    int    op     = h[0] & 0x0f;
    int    fin    = (h[0] & 0x80) != 0;
    int    rsv    = (h[0] & 0x70) != 0;
    int    masked = (h[1] & 0x80) != 0;
    size_t plen   = h[1] & 0x7f;

    if (op == 0x08) return -1;   /* close frame */
    if (!fin || rsv) return -1;   /* fragmented/extensions unsupported */
    if (op != 0x01 && op != 0x09 && op != 0x0a) return -1;

    if (plen == 126) {
        unsigned char e[2];
        if (ssl_read_full(ssl, e, 2) < 0) return -1;
        plen = (e[0] << 8) | e[1];
    } else if (plen == 127) {
        unsigned char e[8];
        if (ssl_read_full(ssl, e, 8) < 0) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i];
    }

    if ((op == 0x09 || op == 0x0a) && plen > 125) return -1;
    if (!masked) return -1;       /* RFC 6455: client frames must be masked */

    unsigned char mk[4] = {0};
    if (ssl_read_full(ssl, mk, 4) < 0) return -1;

    /* Compare as size_t to avoid signed-int overflow when plen > INT_MAX. */
    if (maxlen <= 0 || plen >= (size_t)maxlen) {
        if (plen > WS_MAX_OVERSIZE_DRAIN) {
            return -1;
        }
        char discard[4096];
        size_t remaining = plen;
        while (remaining > 0) {
            int chunk = remaining > sizeof(discard)
                ? (int)sizeof(discard)
                : (int)remaining;
            if (ssl_read_full(ssl, discard, chunk) < 0) return -1;
            remaining -= (size_t)chunk;
        }
        out[0] = '\0';
        metrics_msg_oversized();
        return -2;  /* Signal "oversized frame" so caller can send an error. */
    }

    char *pl = (char *)malloc(plen + 1);
    if (!pl) return -1;
    if (plen > 0 && ssl_read_full(ssl, pl, (int)plen) < 0) {
        free(pl); return -1;
    }
    for (size_t i = 0; i < plen; i++) pl[i] ^= mk[i & 3];
    pl[plen] = '\0';
    memcpy(out, pl, plen + 1);
    free(pl);

    metrics_ws_frame_recv(plen);
    metrics_lat_ws_recv_us(metrics_now_us() - t0);

    if (op == 0x09) {   /* ping — send pong */
        unsigned char pong[2] = {0x8A, 0x00};
        SSL_write(ssl, pong, 2);
        return 0;
    }
    if (op == 0x0a) return 0;     /* pong */
    return (int)plen;
}
