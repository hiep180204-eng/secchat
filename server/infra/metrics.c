/*
 * infra/metrics.c — đo đạc và thống kê hiệu năng server (in-process).
 *
 * Gom các bộ đếm (kết nối, auth, tin nhắn, DB, IO...) và histogram độ trễ vào một
 * struct toàn cục g_m được bảo vệ bằng mutex. Một thread nền mỗi giây ghi snapshot
 * ra /tmp/chat_metrics.json cho công cụ ngoài (dashboard) đọc. Mọi hàm metrics_*
 * đều an toàn đa luồng. Trên Linux còn đọc thêm RSS/VSZ và %CPU từ /proc/self.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
  #define SLEEP_1S()  Sleep(1000)
  #undef  g_mtx
  static CRITICAL_SECTION g_mtx;
  #define MTX_LOCK()   EnterCriticalSection(&g_mtx)
  #define MTX_UNLOCK() LeaveCriticalSection(&g_mtx)
  static HANDLE g_tid;
  #define THREAD_FUNC DWORD WINAPI
  #define THREAD_RETURN return 0
#else
  #include <unistd.h>
  #include <pthread.h>
  #include <sys/types.h>
  #define SLEEP_1S()  sleep(1)
  static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
  #define MTX_LOCK()   pthread_mutex_lock(&g_mtx)
  #define MTX_UNLOCK() pthread_mutex_unlock(&g_mtx)
  static pthread_t g_tid;
  #define THREAD_FUNC  void *
  #define THREAD_RETURN return NULL
#endif

#include "metrics.h"

/* ── Histogram bucket upper bounds in microseconds ─────────────
   Matches the HIST_BUCKETS=12 definition in metrics.h            */
static const uint64_t BOUNDS_US[HIST_BUCKETS] = {
    100, 250, 500, 1000, 2500, 5000,
    10000, 25000, 50000, 100000, 1000000, UINT64_MAX
};

static const char *BOUNDS_LABEL[HIST_BUCKETS] = {
    "100us","250us","500us","1ms","2.5ms","5ms",
    "10ms","25ms","50ms","100ms","1s","inf"
};

/* ── Global state ───────────────────────────────────────────── */
static Metrics g_m      = {0};
static int     g_running = 0;

/* ── Histogram helpers ──────────────────────────────────────── */

/* Ghi một quan sát độ trễ vào histogram: tăng tổng và bucket tương ứng. */
static void hist_obs(Histogram *h, uint64_t us)
{
    h->sum_us += us;
    h->total++;
    for (int i = 0; i < HIST_BUCKETS - 1; i++) {
        if (us <= BOUNDS_US[i]) {
            h->counts[i]++;
            return;
        }
    }
    h->counts[HIST_BUCKETS - 1]++;
}

/* Ước lượng phân vị p (vd p50/p95/p99) từ histogram đã tích lũy. */
static uint64_t hist_pctile(const Histogram *h, int p)
{
    if (h->total == 0) return 0;
    uint64_t target = (h->total * (uint64_t)p + 99) / 100;
    uint64_t cum = 0;
    for (int i = 0; i < HIST_BUCKETS; i++) {
        cum += h->counts[i];
        if (cum >= target)
            return (BOUNDS_US[i] == UINT64_MAX) ? 10000000ULL : BOUNDS_US[i];
    }
    return BOUNDS_US[HIST_BUCKETS - 1];
}

/* ── System metrics (Linux only) ────────────────────────────── */
#ifdef __linux__

/* Đọc RSS/VSZ (KB) của tiến trình từ /proc/self/status. */
static void read_proc_memory(long *rss_kb, long *vsz_kb)
{
    *rss_kb = 0; *vsz_kb = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0)
            sscanf(line + 6, "%ld", rss_kb);
        else if (strncmp(line, "VmSize:", 7) == 0)
            sscanf(line + 7, "%ld", vsz_kb);
    }
    fclose(f);
}

static uint64_t g_cpu_last_j  = 0;
static uint64_t g_cpu_last_us = 0;
static double   g_cpu_pct     = 0.0;

/* Tính %CPU của tiến trình giữa hai lần gọi (jiffies CPU / thời gian thực trôi qua). */
static void update_cpu_pct(void)
{
    FILE *f = fopen("/proc/self/stat", "r");
    if (!f) return;
    unsigned long utime = 0, stime = 0;
    int parsed = fscanf(f,
                        "%*d %*s %*c %*d %*d %*d %*d %*d %*u "
                        "%*u %*u %*u %*u %lu %lu",
                        &utime, &stime);
    fclose(f);
    if (parsed != 2) return;

    uint64_t j    = (uint64_t)(utime + stime);
    uint64_t wall = metrics_now_us();

    if (g_cpu_last_j > 0 && wall > g_cpu_last_us) {
        long hz = sysconf(_SC_CLK_TCK);
        if (hz <= 0) hz = 100;
        double dj = (double)(j - g_cpu_last_j);
        double dw = (double)(wall - g_cpu_last_us) / 1e6;
        g_cpu_pct = (dj / (double)hz) / dw * 100.0;
        if (g_cpu_pct < 0.0)   g_cpu_pct = 0.0;
        if (g_cpu_pct > 100.0) g_cpu_pct = 100.0;
    }
    g_cpu_last_j  = j;
    g_cpu_last_us = wall;
}

#endif /* __linux__ */

/* ── Background snapshot writer thread ─────────────────────── */

/* Thread nền: mỗi giây cập nhật %CPU và ghi snapshot JSON ra /tmp/chat_metrics.json. */
static THREAD_FUNC writer_thread(void *arg)
{
    (void)arg;
    while (g_running) {
        SLEEP_1S();
        if (!g_running) break;

#ifdef __linux__
        update_cpu_pct();
#endif
        char *json = metrics_snapshot_json();
        if (json) {
            FILE *f = fopen("/tmp/chat_metrics.json", "w");
            if (f) { fputs(json, f); fclose(f); }
            free(json);
        }
    }
    THREAD_RETURN;
}

/* ── Init / stop ─────────────────────────────────────────────── */

/* Khởi tạo bộ đếm về 0, ghi thời điểm bắt đầu và khởi động thread ghi snapshot. */
void metrics_init(void)
{
#ifdef _WIN32
    InitializeCriticalSection(&g_mtx);
#endif
    MTX_LOCK();
    memset(&g_m, 0, sizeof(g_m));
    g_m.start_time = (uint64_t)time(NULL);
    MTX_UNLOCK();

    g_running = 1;
#ifdef _WIN32
    g_tid = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)writer_thread, NULL, 0, NULL);
    if (g_tid) CloseHandle(g_tid);
#else
    pthread_create(&g_tid, NULL, writer_thread, NULL);
    pthread_detach(g_tid);
#endif
}

void metrics_stop(void)
{
    g_running = 0;
}

/* ── Bộ đếm ───────────────────────────────────────────────────
   INC tăng một trường của g_m dưới mutex. Phần lớn hàm metrics_*
   bên dưới chỉ là wrapper một dòng quanh INC.                     */

#define INC(field) do { MTX_LOCK(); g_m.field++; MTX_UNLOCK(); } while(0)

/* Tăng số kết nối được chấp nhận và đang hoạt động, cập nhật đỉnh đồng thời. */
void metrics_conn_accepted_and_opened(void)
{
    MTX_LOCK();
    g_m.conn_accepted++;
    g_m.conn_active++;
    if (g_m.conn_active > g_m.conn_peak)
        g_m.conn_peak = g_m.conn_active;
    MTX_UNLOCK();
}

void metrics_conn_rejected(void)   { INC(conn_rejected); }

void metrics_conn_closed(void)
{
    MTX_LOCK();
    if (g_m.conn_active > 0) g_m.conn_active--;
    MTX_UNLOCK();
}

void metrics_auth_ok(void)              { INC(auth_ok); }
void metrics_auth_fail(void)            { INC(auth_fail); }
void metrics_auth_ratelimited(void)     { INC(auth_ratelimited); }
void metrics_register_ok(void)          { INC(registers); }
void metrics_msg_sent(void)             { INC(msgs_sent); }
void metrics_msg_oversized(void)        { INC(msgs_oversized); }
void metrics_search_ok(void)            { INC(searches); }
void metrics_search_ratelimited(void)   { INC(search_ratelimited); }
void metrics_preauth_timeout(void)      { INC(preauth_timeouts); }
void metrics_validation_error(void)     { INC(validation_errors); }
void metrics_msg_edited(void)           { INC(msgs_edited); }
void metrics_msg_deleted(void)          { INC(msgs_deleted); }
void metrics_group_created(void)        { INC(groups_created); }
void metrics_reaction_added(void)       { INC(reactions_added); }

void metrics_ws_frame_recv(size_t bytes)
{
    MTX_LOCK();
    g_m.ws_frames_recv++;
    g_m.ws_bytes_recv += (uint64_t)bytes;
    MTX_UNLOCK();
}

void metrics_ws_frame_sent(size_t bytes)
{
    MTX_LOCK();
    g_m.ws_frames_sent++;
    g_m.ws_bytes_sent += (uint64_t)bytes;
    MTX_UNLOCK();
}

void metrics_db_query(int ok)
{
    MTX_LOCK();
    g_m.db_queries++;
    if (!ok) g_m.db_errors++;
    MTX_UNLOCK();
}

/* ── Latency observations ────────────────────────────────────── */

void metrics_lat_auth_us(uint64_t us)
{
    MTX_LOCK(); hist_obs(&g_m.lat_auth, us); MTX_UNLOCK();
}
void metrics_lat_msg_us(uint64_t us)
{
    MTX_LOCK(); hist_obs(&g_m.lat_msg, us); MTX_UNLOCK();
}
void metrics_lat_db_us(uint64_t us)
{
    MTX_LOCK(); hist_obs(&g_m.lat_db, us); MTX_UNLOCK();
}
void metrics_lat_ws_recv_us(uint64_t us)
{
    MTX_LOCK(); hist_obs(&g_m.lat_ws_recv, us); MTX_UNLOCK();
}
void metrics_lat_group_us(uint64_t us)
{
    MTX_LOCK(); hist_obs(&g_m.lat_group, us); MTX_UNLOCK();
}

/* ── Monotonic clock ─────────────────────────────────────────── */

/* Đồng hồ đơn điệu (monotonic), đơn vị micro giây — dùng để đo độ trễ. */
uint64_t metrics_now_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (uint64_t)(cnt.QuadPart * 1000000ULL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL
         + (uint64_t)ts.tv_nsec / 1000ULL;
#endif
}

/* ── JSON serialization ──────────────────────────────────────── */

/* Nối JSON cho một histogram: total/avg/p50/p95/p99 và danh sách bucket. */
static void append_hist(char *buf, size_t *pos, size_t cap,
                         const char *name, const Histogram *h)
{
    uint64_t p50 = hist_pctile(h, 50);
    uint64_t p95 = hist_pctile(h, 95);
    uint64_t p99 = hist_pctile(h, 99);
    uint64_t avg = h->total ? h->sum_us / h->total : 0;

    int n = snprintf(buf + *pos, cap - *pos,
                     "\"%s\":{"
                     "\"total\":%llu,\"avg_us\":%llu,"
                     "\"p50_us\":%llu,\"p95_us\":%llu,\"p99_us\":%llu,"
                     "\"buckets\":[",
                     name,
                     (unsigned long long)h->total,
                     (unsigned long long)avg,
                     (unsigned long long)p50,
                     (unsigned long long)p95,
                     (unsigned long long)p99);
    if (n > 0) *pos += (size_t)n;

    for (int i = 0; i < HIST_BUCKETS; i++) {
        if (*pos >= cap - 8) break;
        if (i > 0 && *pos < cap - 1) buf[(*pos)++] = ',';
        n = snprintf(buf + *pos, cap - *pos,
                     "{\"le\":\"%s\",\"count\":%llu}",
                     BOUNDS_LABEL[i],
                     (unsigned long long)h->counts[i]);
        if (n > 0) *pos += (size_t)n;
    }
    if (*pos < cap - 2) {
        buf[(*pos)++] = ']';
        buf[(*pos)++] = '}';
    }
}

/* Tạo chuỗi JSON tổng hợp toàn bộ metrics (chụp g_m dưới mutex). Caller phải free(). */
char *metrics_snapshot_json(void)
{
    Metrics snap;
    MTX_LOCK();
    snap = g_m;
    MTX_UNLOCK();

    uint64_t uptime = (uint64_t)time(NULL) - snap.start_time;

    long   rss_kb = 0, vsz_kb = 0;
    double cpu_pct = 0.0;
#ifdef __linux__
    read_proc_memory(&rss_kb, &vsz_kb);
    cpu_pct = g_cpu_pct;
#endif

    size_t cap = 16384;
    char  *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    size_t pos = 0;

    int n = snprintf(buf + pos, cap - pos,
        "{"
        "\"uptime_s\":%llu,"
        "\"connections\":{"
            "\"accepted\":%llu,\"rejected\":%llu,"
            "\"active\":%llu,\"peak\":%llu"
        "},"
        "\"auth\":{"
            "\"ok\":%llu,\"fail\":%llu,"
            "\"ratelimited\":%llu,\"registers\":%llu"
        "},"
        "\"messages\":{"
            "\"sent\":%llu,\"oversized\":%llu,"
            "\"edited\":%llu,\"deleted\":%llu,"
            "\"searches\":%llu,\"search_ratelimited\":%llu"
        "},"
        "\"groups\":{"
            "\"created\":%llu"
        "},"
        "\"reactions\":{"
            "\"added\":%llu"
        "},"
        "\"io\":{"
            "\"ws_frames_recv\":%llu,\"ws_frames_sent\":%llu,"
            "\"ws_bytes_recv\":%llu,\"ws_bytes_sent\":%llu"
        "},"
        "\"database\":{"
            "\"queries\":%llu,\"errors\":%llu"
        "},"
        "\"security\":{"
            "\"preauth_timeouts\":%llu,\"validation_errors\":%llu"
        "},"
        "\"system\":{"
            "\"rss_kb\":%ld,\"vsz_kb\":%ld,\"cpu_pct\":%.2f"
        "},"
        "\"latency\":{",
        (unsigned long long)uptime,
        (unsigned long long)snap.conn_accepted,
        (unsigned long long)snap.conn_rejected,
        (unsigned long long)snap.conn_active,
        (unsigned long long)snap.conn_peak,
        (unsigned long long)snap.auth_ok,
        (unsigned long long)snap.auth_fail,
        (unsigned long long)snap.auth_ratelimited,
        (unsigned long long)snap.registers,
        (unsigned long long)snap.msgs_sent,
        (unsigned long long)snap.msgs_oversized,
        (unsigned long long)snap.msgs_edited,
        (unsigned long long)snap.msgs_deleted,
        (unsigned long long)snap.searches,
        (unsigned long long)snap.search_ratelimited,
        (unsigned long long)snap.groups_created,
        (unsigned long long)snap.reactions_added,
        (unsigned long long)snap.ws_frames_recv,
        (unsigned long long)snap.ws_frames_sent,
        (unsigned long long)snap.ws_bytes_recv,
        (unsigned long long)snap.ws_bytes_sent,
        (unsigned long long)snap.db_queries,
        (unsigned long long)snap.db_errors,
        (unsigned long long)snap.preauth_timeouts,
        (unsigned long long)snap.validation_errors,
        rss_kb, vsz_kb, cpu_pct);
    if (n > 0) pos += (size_t)n;

    append_hist(buf, &pos, cap, "auth",    &snap.lat_auth);
    if (pos < cap - 1) buf[pos++] = ',';
    append_hist(buf, &pos, cap, "msg",     &snap.lat_msg);
    if (pos < cap - 1) buf[pos++] = ',';
    append_hist(buf, &pos, cap, "db",      &snap.lat_db);
    if (pos < cap - 1) buf[pos++] = ',';
    append_hist(buf, &pos, cap, "ws_recv", &snap.lat_ws_recv);
    if (pos < cap - 1) buf[pos++] = ',';
    append_hist(buf, &pos, cap, "group",   &snap.lat_group);

    if (pos < cap - 3) {
        buf[pos++] = '}';   /* close latency */
        buf[pos++] = '}';   /* close root */
        buf[pos]   = '\0';
    }

    return buf;
}
