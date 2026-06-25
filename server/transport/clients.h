#ifndef CLIENTS_H
#define CLIENTS_H

#include <time.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
#define SOCKET_T SOCKET
#else
#define SOCKET_T int
#define INVALID_SOCKET (-1)
#endif

#define MAX_CLIENTS  200
#define USERNAME_LEN 64
#define IP_LEN       46   /* enough for IPv4-mapped IPv6 */

typedef struct
{
    SOCKET_T fd;
    SSL     *ssl;            /* TLS connection (NULL until handshake) */
    int      active;
    int      ws_ready;
    char     username[USERNAME_LEN];
    int      user_id;
    char     ip[IP_LEN];     /* remote IP for auth rate limiting */
    time_t   connected_at;  /* timestamp for pre-auth timeout */
    time_t   last_search;   /* search rate limiting (1 req/s) */
} Client;

/* Must be called once at startup before any other clients_* call. */
void clients_init(void);

/* Add a new connection. Returns slot index, or -1 if full. */
int clients_add(SOCKET_T fd);

/* Mark slot as inactive and broadcast offline presence.
   Only notifies presence if no other session for that user exists. */
void clients_remove(int idx);

/* Send JSON to a specific slot (no-op if not ws_ready). */
void clients_send(int idx, const char *json);

/* Send JSON to every active slot logged in as target_uid. */
void clients_send_to_uid(int target_uid, const char *json);

/* Clear all authenticated sessions for uid except keep_idx and notify them.
   Returns the number of sessions replaced. */
int clients_replace_other_sessions(int uid, int keep_idx);

/* Mark slot ws_ready after handshake succeeds. */
void clients_set_ready(int idx);

/* Store the SSL pointer in the client slot. */
void clients_set_ssl(int idx, SSL *ssl);

/* Accessors — read-only snapshots (lock held internally). */
int clients_get_uid(int idx);
void clients_get_username(int idx, char out[USERNAME_LEN]);

/* Broadcast JSON to every member of a conversation (queries DB internally). */
void clients_broadcast_conv(long long conv_id, const char *json);

/* Package-internal: direct access to a slot for main.c (setting user_id/username).
   Returns NULL if idx is out of range. */
Client *clients_slot(int idx);

/* Graceful logout: clear the slot's auth identity and broadcast offline presence
   only when no other session for the same uid remains active.
   Returns the uid that was logged out, or -1 if not authenticated. */
int clients_logout_user(int idx);

/* Store and retrieve the remote IP string for a slot. */
void clients_set_ip(int idx, const char *ip);
void clients_get_ip(int idx, char out[IP_LEN]);

/* Close any active, unauthenticated slots older than timeout_secs. */
void clients_timeout_check(int timeout_secs);

/* Search rate limiter: returns 1 if the slot may issue a search now. */
int clients_check_search_rate(int idx);

/* Return 1 if any active, authenticated session exists for uid (for offline
   notification queueing). */
int clients_is_online(int uid);

#endif /* CLIENTS_H */
