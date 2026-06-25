#ifndef WS_H
#define WS_H

#include <stddef.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
typedef int socklen_t;
#define SOCKET_T SOCKET
#else
#define SOCKET_T int
#endif

/* Perform WebSocket upgrade handshake over TLS.
   `req` is the raw HTTP request string received from the client.
   Returns 1 on success, 0 on failure. */
int ws_handshake(SSL *ssl, const char *req);

/* Validate an HTTP WebSocket upgrade request and build Sec-WebSocket-Accept.
   This pure helper is used by ws_handshake() and by sanitizer/fuzz tests. */
int ws_build_accept(const char *req, char *accept, size_t accept_len);

/* Decode a complete masked client WebSocket frame from memory.
   This pure helper mirrors the frame validation rules used by ws_recv() and is
   intended for sanitizer/fuzz tests that should not need a TLS socket.
   Returns payload length, 0 for ping/pong, -1 on malformed/incomplete input,
   or -2 when the payload is larger than out[maxlen]. */
int ws_decode_client_frame(const unsigned char *frame, size_t frame_len,
                           char *out, size_t maxlen, int *opcode_out);

/* Send `data` as a WebSocket text frame over TLS.
   Returns bytes sent, or -1 on allocation failure / write error. */
int ws_send(SSL *ssl, const char *data);

/* Receive one WebSocket frame into `out[maxlen]` over TLS.
   Returns payload length, 0 for ping/pong, -1 on protocol error/close,
   or -2 when the frame is larger than maxlen. */
int ws_recv(SSL *ssl, char *out, int maxlen);

#endif /* WS_H */
