/*
 * infra/db_pool.c — pool kết nối MySQL có tự hồi phục.
 *
 * Giữ sẵn một số connection để các handler mượn/trả nhanh thay vì mở mới mỗi
 * request. Một thread nền định kỳ kiểm tra và mở lại connection chết, nên khi
 * DB tạm gián đoạn rồi sống lại, server tự phục hồi mà không cần restart.
 */
#include "db_pool.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifndef _WIN32
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#else
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#endif

#include <pthread.h>

#include "log.h"

#define POOL_SIZE 8   /* number of MySQL connections to maintain */

typedef struct {
    MYSQL *conn;
    int    in_use;
} PoolSlot;

static PoolSlot         g_slots[POOL_SIZE];
static pthread_mutex_t  g_pool_mtx  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_pool_cond = PTHREAD_COND_INITIALIZER;
static int              g_pool_ready = 0;
static atomic_int       g_db_health_ok = 0;
static atomic_int       g_health_thread_started = 0;

/* Connect one MySQL handle. Startup may retry for a long time, but runtime
 * reconnects must be quick so one broken database does not block all clients. */
static MYSQL *connect_one(const char *host, unsigned int port,
                           const char *user, const char *pass,
                           const char *name,
                           int attempts,
                           int sleep_ms)
{
    MYSQL *c = mysql_init(NULL);
    if (!c) return NULL;

    unsigned int timeout_sec = 1;
    mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_sec);
    mysql_options(c, MYSQL_OPT_READ_TIMEOUT, &timeout_sec);
    mysql_options(c, MYSQL_OPT_WRITE_TIMEOUT, &timeout_sec);

    if (attempts < 1) attempts = 1;
    for (int attempt = 0; attempt < attempts; attempt++) {
        if (mysql_real_connect(c, host, user, pass, name, port, NULL, 0))
            break;
        log_info("db_pool: connect attempt %d/%d failed: %s",
                 attempt + 1, attempts, mysql_error(c));
        if (sleep_ms > 0 && attempt + 1 < attempts)
            SLEEP_MS(sleep_ms);
    }
    if (mysql_ping(c) != 0) {
        mysql_close(c);
        return NULL;
    }
    mysql_set_character_set(c, "utf8mb4");
    return c;
}

#ifndef _WIN32
/* Thread nền: định kỳ ping và mở lại các connection trong pool bị rớt. */
static void *db_health_thread(void *arg)
{
    (void)arg;
    while (1) {
        MYSQL *conn = connect_one(
            g_config.db_host, (unsigned int)g_config.db_port,
            g_config.db_user, g_config.db_pass,
            g_config.db_name,
            1, 0);
        if (conn) {
            mysql_close(conn);
            atomic_store(&g_db_health_ok, 1);
        } else {
            atomic_store(&g_db_health_ok, 0);
        }
        SLEEP_MS(2000);
    }
    return NULL;
}
#endif

/* Khởi tạo pool (đọc DB_HOST/USER/PASS/NAME từ config). Trả 1 nếu thành công. */
int db_pool_init(void)
{
    const char   *host = g_config.db_host;
    unsigned int  port = (unsigned int)g_config.db_port;
    const char   *user = g_config.db_user;
    const char   *pass = g_config.db_pass;
    const char   *name = g_config.db_name;

    pthread_mutex_lock(&g_pool_mtx);
    for (int i = 0; i < POOL_SIZE; i++) {
        g_slots[i].conn   = connect_one(host, port, user, pass, name, 30, 2000);
        g_slots[i].in_use = 0;
        if (!g_slots[i].conn) {
            log_warn("db_pool: failed to open slot %d", i);
            for (int j = 0; j < i; j++) {
                if (g_slots[j].conn) {
                    mysql_close(g_slots[j].conn);
                    g_slots[j].conn = NULL;
                    g_slots[j].in_use = 0;
                }
            }
            pthread_mutex_unlock(&g_pool_mtx);
            return 0;
        }
    }
    g_pool_ready = 1;
    atomic_store(&g_db_health_ok, 1);
    pthread_mutex_unlock(&g_pool_mtx);

#ifndef _WIN32
    int expected = 0;
    if (atomic_compare_exchange_strong(&g_health_thread_started, &expected, 1)) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, db_health_thread, NULL) == 0) {
            pthread_detach(tid);
        } else {
            atomic_store(&g_health_thread_started, 0);
        }
    }
#endif

    log_info("db_pool: %d connections ready (%s@%s:%u/%s)",
             POOL_SIZE, user, host, port, name);
    return 1;
}

/* Mượn một connection từ pool; trả NULL nếu DB đang chết để handler fail nhanh
 * thay vì treo sau mutex của pool. */
MYSQL *db_pool_acquire(void)
{
    pthread_mutex_lock(&g_pool_mtx);
    while (1) {
        if (!g_pool_ready) {
            pthread_mutex_unlock(&g_pool_mtx);
            return NULL;
        }
        int busy_slots = 0;
        int db_unavailable = 0;
        for (int i = 0; i < POOL_SIZE; i++) {
            if (g_slots[i].in_use) {
                busy_slots++;
                continue;
            }
            if (!g_slots[i].conn) {
                g_slots[i].conn = connect_one(
                    g_config.db_host, (unsigned int)g_config.db_port,
                    g_config.db_user, g_config.db_pass,
                    g_config.db_name,
                    1, 0);
                if (!g_slots[i].conn) {
                    atomic_store(&g_db_health_ok, 0);
                    db_unavailable = 1;
                    break;
                }
            }
            if (g_slots[i].conn) {
                /* Ping to detect stale connection and reconnect if needed */
                if (mysql_ping(g_slots[i].conn) != 0) {
                    mysql_close(g_slots[i].conn);
                    g_slots[i].conn = connect_one(
                        g_config.db_host, (unsigned int)g_config.db_port,
                        g_config.db_user, g_config.db_pass,
                        g_config.db_name,
                        1, 0);
                    if (!g_slots[i].conn) {
                        atomic_store(&g_db_health_ok, 0);
                        db_unavailable = 1;
                        break;
                    }
                }
                g_slots[i].in_use = 1;
                atomic_store(&g_db_health_ok, 1);
                pthread_mutex_unlock(&g_pool_mtx);
                return g_slots[i].conn;
            }
        }
        if (busy_slots > 0 && !db_unavailable) {
            /* All remaining live slots are busy — wait for a release signal. */
            pthread_cond_wait(&g_pool_cond, &g_pool_mtx);
        } else {
            pthread_mutex_unlock(&g_pool_mtx);
            return NULL;
        }
    }
}

/* Trả connection về pool để request khác dùng lại. */
void db_pool_release(MYSQL *conn)
{
    if (!conn) return;
    pthread_mutex_lock(&g_pool_mtx);
    for (int i = 0; i < POOL_SIZE; i++) {
        if (g_slots[i].conn == conn) {
            g_slots[i].in_use = 0;
            pthread_cond_signal(&g_pool_cond);
            break;
        }
    }
    pthread_mutex_unlock(&g_pool_mtx);
}

/* Ping nhanh DB một lần (dùng cho /readyz và test fault-injection). */
int db_pool_ping_once(void)
{
    return atomic_load(&g_db_health_ok) ? 1 : 0;
}
