#ifndef INFRA_DB_POOL_H
#define INFRA_DB_POOL_H

#include <mysql/mysql.h>

/* Initialise the connection pool (call once from db_connect()).
 * Reads DB_HOST / DB_USER / DB_PASS / DB_NAME env vars like db.c does.
 * Returns 1 on success, 0 on failure. */
int  db_pool_init(void);

/* Acquire a connection from the pool.
 * Blocks only when all live slots are busy. If the database is down and no
 * slot can reconnect quickly, returns NULL so request handlers fail fast
 * instead of wedging behind the pool mutex. */
MYSQL *db_pool_acquire(void);

/* Return a connection to the pool. */
void db_pool_release(MYSQL *conn);

/* Fast readiness probe used by /readyz and fault-injection tests. */
int db_pool_ping_once(void);

/* Convenience macro: borrow conn from the pool for a scoped block.
 *
 * Usage:
 *   DB_WITH(c) {
 *       mysql_query(c, "SELECT 1");
 *   }
 *
 * The connection is automatically released when the block exits (including
 * via break/continue/return — the for-loop guarantees release on every path). */
#define DB_WITH(varname) \
    for (MYSQL *(varname) = db_pool_acquire(); \
         (varname) != NULL; \
         db_pool_release(varname), (varname) = NULL)

#endif /* INFRA_DB_POOL_H */
