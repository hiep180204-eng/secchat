/*
 * infra/db_lifecycle.c — vòng đời kết nối MySQL singleton (connect / close).
 *
 * Moved from root db.c.  The db_set_offline bridge was removed;
 * transport/clients.c now calls presence_broadcast_offline() directly.
 */

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

#include <mysql/mysql.h>

#include "db_lifecycle.h"
#include "log.h"
#include "migrate.h"
#include "db_pool.h"
#include "config.h"

static MYSQL *g_db = NULL;

int db_connect(void)
{
    g_db = mysql_init(NULL);
    if (!g_db)
        return 0;

    const char   *host = g_config.db_host;
    unsigned int  port = (unsigned int)g_config.db_port;
    const char   *user = g_config.db_user;
    const char   *pass = g_config.db_pass;
    const char   *name = g_config.db_name;

    for (int attempt = 0; attempt < 60; attempt++) {
        if (mysql_real_connect(g_db, host, user, pass, name, port, NULL, 0))
            break;
        log_info("DB connect attempt %d/60 failed: %s",
                 attempt + 1, mysql_error(g_db));
        SLEEP_MS(2000);
    }
    if (mysql_ping(g_db) != 0) {
        fprintf(stderr, "Cannot connect to MySQL after 60 attempts\n");
        mysql_close(g_db);
        g_db = NULL;
        return 0;
    }
    mysql_set_character_set(g_db, "utf8mb4");

    if (!migrate_run(g_db, g_config.migrations_dir))
        log_warn("db_connect: some migrations failed — check logs");

    if (!db_pool_init())
        log_warn("db_connect: connection pool init failed");

    log_info("MySQL connected -> %s@%s:%u/%s", user, host, port, name);
    return 1;
}

void db_close(void)
{
    if (g_db) {
        mysql_close(g_db);
        g_db = NULL;
    }
}
