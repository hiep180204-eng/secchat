/*
 * infra/ratelimit.c — giới hạn tốc độ gửi tin theo từng user (token bucket)
 *
 * Each UID gets a bucket that refills at 1 token per REFILL_SECS
 * up to CAPACITY tokens.  Sending a message costs 1 token.
 * When the bucket is empty the message is rejected.
 *
 * Uses open-addressing with linear probing; table size is a power of 2
 * chosen to handle g_config.max_clients comfortably.
 */

#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <pthread.h>
#endif

#include "ratelimit.h"
#include "log.h"

#define RL_BUCKETS    4096   /* must be power-of-2                           */
#define CAPACITY        10   /* max burst tokens                             */
#define REFILL_SECS      1   /* +1 token per second                          */

typedef struct {
    int    uid;          /* 0 = empty slot                                   */
    int    tokens;       /* 0..CAPACITY                                      */
    time_t last_refill;
} RLBucket;

static RLBucket g_rl[RL_BUCKETS];

#ifdef _WIN32
static CRITICAL_SECTION g_rl_mtx;
#define RL_LOCK()   EnterCriticalSection(&g_rl_mtx)
#define RL_UNLOCK() LeaveCriticalSection(&g_rl_mtx)
#else
static pthread_mutex_t g_rl_mtx = PTHREAD_MUTEX_INITIALIZER;
#define RL_LOCK()   pthread_mutex_lock(&g_rl_mtx)
#define RL_UNLOCK() pthread_mutex_unlock(&g_rl_mtx)
#endif

void ratelimit_init(void)
{
    memset(g_rl, 0, sizeof(g_rl));
#ifdef _WIN32
    InitializeCriticalSection(&g_rl_mtx);
#endif
    log_info("ratelimit: token bucket ready"
             " (capacity=%d, +1 token/%ds)", CAPACITY, REFILL_SECS);
}

/* Open-addressing linear-probe slot finder */
static int rl_slot(int uid)
{
    unsigned int h = (unsigned int)(uid * 2654435761u) % RL_BUCKETS;
    for (int i = 0; i < RL_BUCKETS; i++) {
        int s = (int)((h + (unsigned int)i) % RL_BUCKETS);
        if (g_rl[s].uid == 0 || g_rl[s].uid == uid)
            return s;
    }
    return -1;   /* table full — fail-open */
}

int ratelimit_check(int uid)
{
    if (uid <= 0) return 1;

    time_t now = time(NULL);
    RL_LOCK();

    int s = rl_slot(uid);
    if (s < 0) {
        RL_UNLOCK();
        return 1;   /* fail-open: table full */
    }

    RLBucket *b = &g_rl[s];
    if (b->uid == 0) {
        /* New entry — full bucket */
        b->uid        = uid;
        b->tokens     = CAPACITY;
        b->last_refill = now;
    }

    /* Refill proportional to elapsed time */
    long elapsed = (long)(now - b->last_refill);
    if (elapsed >= REFILL_SECS) {
        int add = (int)(elapsed / REFILL_SECS);
        b->tokens += add;
        if (b->tokens > CAPACITY) b->tokens = CAPACITY;
        b->last_refill = now;
    }

    int allowed = (b->tokens > 0);
    if (allowed) b->tokens--;

    RL_UNLOCK();

    if (!allowed)
        log_warn("ratelimit: uid=%d throttled (bucket empty)", uid);
    return allowed;
}
