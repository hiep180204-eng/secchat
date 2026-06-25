#ifndef SECCHAT_INFRA_METRICS_H
#define SECCHAT_INFRA_METRICS_H

/*
 * infra/metrics.h — in-process performance monitoring for SecChat server
 *
 * All counters are protected by a single internal mutex.
 * Callers just call the one-liner helpers below — no locking needed.
 *
 * A background thread writes /tmp/chat_metrics.json every second.
 * Authenticated clients can also request a snapshot via "get_metrics".
 * The HTTP control plane (/metrics) also reads from this module.
 */

#include <stdint.h>
#include <stddef.h>

/* ── Latency histogram ────────────────────────────────────────────
   12 log-scale buckets (µs upper bounds):
     [0] ≤100µs   [1] ≤250µs   [2] ≤500µs   [3] ≤1ms
     [4] ≤2.5ms   [5] ≤5ms     [6] ≤10ms    [7] ≤25ms
     [8] ≤50ms    [9] ≤100ms   [10] ≤1s     [11] >1s
 ─────────────────────────────────────────────────────────────── */
#define HIST_BUCKETS 12

typedef struct {
    uint64_t counts[HIST_BUCKETS];
    uint64_t sum_us;   /* cumulative microseconds */
    uint64_t total;    /* total observations */
} Histogram;

/* ── Aggregated metrics ───────────────────────────────────────── */
typedef struct {
    /* Connection lifecycle */
    uint64_t conn_accepted;
    uint64_t conn_rejected;
    uint64_t conn_active;
    uint64_t conn_peak;

    /* Authentication */
    uint64_t auth_ok;
    uint64_t auth_fail;
    uint64_t auth_ratelimited;
    uint64_t registers;

    /* Messaging */
    uint64_t msgs_sent;
    uint64_t msgs_oversized;
    uint64_t searches;
    uint64_t search_ratelimited;

    /* WebSocket I/O */
    uint64_t ws_frames_recv;
    uint64_t ws_frames_sent;
    uint64_t ws_bytes_recv;
    uint64_t ws_bytes_sent;

    /* Database */
    uint64_t db_queries;
    uint64_t db_errors;

    /* Security */
    uint64_t preauth_timeouts;   /* unauthenticated connection evictions */
    uint64_t validation_errors;  /* domain validation rejections (security signal) */

    /* Extended operations */
    uint64_t msgs_edited;
    uint64_t msgs_deleted;
    uint64_t groups_created;
    uint64_t reactions_added;

    /* Latency histograms */
    Histogram lat_auth;        /* handle_auth() wall-time */
    Histogram lat_msg;         /* send_message wall-time */
    Histogram lat_db;          /* individual mysql_query() */
    Histogram lat_ws_recv;     /* ws_recv() parse time */
    Histogram lat_group;       /* group create wall-time */

    /* Server start time (Unix epoch, set once in metrics_init) */
    uint64_t start_time;
} Metrics;

/* ── Public API ───────────────────────────────────────────────── */

void metrics_init(void);
void metrics_stop(void);

void metrics_conn_accepted_and_opened(void);
void metrics_conn_rejected(void);
void metrics_conn_closed(void);

void metrics_auth_ok(void);
void metrics_auth_fail(void);
void metrics_auth_ratelimited(void);
void metrics_register_ok(void);

void metrics_msg_sent(void);
void metrics_msg_oversized(void);
void metrics_search_ok(void);
void metrics_search_ratelimited(void);

void metrics_ws_frame_recv(size_t bytes);
void metrics_ws_frame_sent(size_t bytes);

void metrics_db_query(int ok);
void metrics_preauth_timeout(void);
void metrics_validation_error(void);

void metrics_msg_edited(void);
void metrics_msg_deleted(void);
void metrics_group_created(void);
void metrics_reaction_added(void);

void metrics_lat_auth_us(uint64_t us);
void metrics_lat_msg_us(uint64_t us);
void metrics_lat_db_us(uint64_t us);
void metrics_lat_ws_recv_us(uint64_t us);
void metrics_lat_group_us(uint64_t us);

uint64_t metrics_now_us(void);

/* Returns an allocated JSON string (caller must free). Returns NULL on failure. */
char *metrics_snapshot_json(void);

#endif /* SECCHAT_INFRA_METRICS_H */
