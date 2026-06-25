/*
 * infra/migrate.c — chạy các file SQL migration lúc server khởi động.
 *
 * Quét thư mục migrations theo thứ tự tên file, áp các migration CHƯA chạy (ghi
 * nhận trong bảng schema_migrations) một cách idempotent. Nhờ vậy schema DB luôn
 * được nâng cấp tự động khi container server lên.
 */
#include "migrate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* POSIX directory scan — works on Linux/macOS (Docker containers).
   On Windows the project builds natively but the server is Docker-only. */
#include <dirent.h>
#include <sys/stat.h>

#include "log.h"

/* ── helpers ────────────────────────────────────────────────── */

/* Chạy MỘT câu SQL (không cần ';' cuối). Trả 1 nếu thành công, 0 nếu lỗi.
   Một số lỗi idempotent (vd bảng đã tồn tại) được bỏ qua có chủ đích. */
static int exec_one(MYSQL *conn, const char *sql, size_t sql_len)
{
    if (mysql_real_query(conn, sql, (unsigned long)sql_len)) {
        /* Ignore idempotent DDL errors so upgraded and fresh databases can share
           the same migration chain. */
        unsigned int err = mysql_errno(conn);
        if (err == 1050 || err == 1060) {
            log_info("migrate: idempotent skip (errno=%u): %.60s...", err, sql);
            return 1;
        }
        log_warn("migrate: mysql_real_query failed (errno=%u): %s | SQL: %.80s...",
                 err, mysql_error(conn), sql);
        return 0;
    }
    /* Consume any result set produced by e.g. SELECT (not expected in DDL). */
    MYSQL_RES *res = mysql_store_result(conn);
    if (res) mysql_free_result(res);
    return 1;
}

/* Split `buf` by ';', strip whitespace/comments, and execute each statement.
   Returns 1 if all succeeded, 0 if any failed. */
static int exec_sql_file(MYSQL *conn, char *buf, size_t len)
{
    int ok = 1;
    char *p   = buf;
    char *end = buf + len;

    while (p < end) {
        /* Skip leading whitespace */
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
            p++;
        if (p >= end) break;

        /* Skip line comments starting with '--' */
        if (p + 1 < end && p[0] == '-' && p[1] == '-') {
            while (p < end && *p != '\n') p++;
            continue;
        }

        /* Find end of statement (';') */
        char *stmt_start = p;
        while (p < end && *p != ';') {
            /* Skip line-comment embedded within a statement */
            if (p + 1 < end && p[0] == '-' && p[1] == '-') {
                while (p < end && *p != '\n') p++;
                continue;
            }
            p++;
        }

        size_t stmt_len = (size_t)(p - stmt_start);

        /* Trim trailing whitespace */
        while (stmt_len > 0 &&
               (stmt_start[stmt_len-1] == ' ' || stmt_start[stmt_len-1] == '\t' ||
                stmt_start[stmt_len-1] == '\r' || stmt_start[stmt_len-1] == '\n'))
            stmt_len--;

        if (stmt_len > 0) {
            if (!exec_one(conn, stmt_start, stmt_len))
                ok = 0;
        }

        if (p < end) p++; /* skip ';' */
    }
    return ok;
}

/* Read entire file into a newly allocated buffer.
   Returns buffer (caller frees) or NULL on error. */
static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_warn("migrate: cannot open %s", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); *out_len = 0; return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* Case-insensitive suffix check */
static int has_sql_suffix(const char *name)
{
    size_t n = strlen(name);
    return (n > 4 && strcasecmp(name + n - 4, ".sql") == 0);
}

/* Compare function for qsort — lexicographic filename order. */
static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

/* ── public API ─────────────────────────────────────────────── */

int migrate_run(MYSQL *conn, const char *migrations_dir)
{
    /* 1. Create schema_migrations tracking table */
    const char *create_tracking =
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version    VARCHAR(80) PRIMARY KEY,"
        " applied_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    if (!exec_one(conn, create_tracking, strlen(create_tracking))) {
        log_warn("migrate: failed to create schema_migrations table");
        return 0;
    }

    /* 2. Open migrations directory */
    DIR *dir = opendir(migrations_dir);
    if (!dir) {
        log_warn("migrate: cannot open migrations dir '%s'", migrations_dir);
        /* Not a fatal error — continue without migrations */
        return 1;
    }

    /* 3. Collect .sql filenames */
    char  *names[256];
    int    n_names = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && n_names < 255) {
        if (!has_sql_suffix(ent->d_name)) continue;
        names[n_names] = strdup(ent->d_name);
        if (names[n_names]) n_names++;
    }
    closedir(dir);

    /* 4. Sort lexicographically */
    qsort(names, (size_t)n_names, sizeof(char *), cmp_str);

    int all_ok = 1;

    /* 5. Apply pending migrations */
    for (int i = 0; i < n_names; i++) {
        const char *fname = names[i];

        /* Version = filename without .sql extension */
        char version[84] = {0};
        size_t nlen = strlen(fname);
        size_t vlen = nlen - 4; /* strip ".sql" */
        if (vlen >= sizeof(version)) vlen = sizeof(version) - 1;
        memcpy(version, fname, vlen);
        version[vlen] = '\0';

        /* Check if already applied */
        char chk[256];
        snprintf(chk, sizeof(chk),
                 "SELECT 1 FROM schema_migrations WHERE version='%s' LIMIT 1",
                 version);
        if (mysql_query(conn, chk) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            int applied = 0;
            if (res) {
                applied = (mysql_fetch_row(res) != NULL);
                mysql_free_result(res);
            }
            if (applied) {
                log_info("migrate: already applied  %s", version);
                free(names[i]);
                continue;
            }
        }

        /* Build full path */
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", migrations_dir, fname);

        log_info("migrate: applying  %s", version);

        size_t flen = 0;
        char  *sql_buf = read_file(path, &flen);
        if (!sql_buf) {
            log_warn("migrate: failed to read %s", path);
            all_ok = 0;
            free(names[i]);
            continue;
        }

        int ok = exec_sql_file(conn, sql_buf, flen);
        free(sql_buf);

        if (!ok) {
            log_warn("migrate: FAILED to apply %s", version);
            all_ok = 0;
            free(names[i]);
            continue;
        }

        /* Record as applied */
        char ins[256];
        snprintf(ins, sizeof(ins),
                 "INSERT IGNORE INTO schema_migrations(version) VALUES('%s')",
                 version);
        mysql_query(conn, ins);

        log_info("migrate: applied   %s  OK", version);
        free(names[i]);
    }

    return all_ok;
}
