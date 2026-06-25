#ifndef INFRA_MIGRATE_H
#define INFRA_MIGRATE_H

#include <mysql/mysql.h>

/* Run all pending migrations from `migrations_dir` (e.g. "repository/migrations").
 *
 * Algorithm:
 *   1. Ensure schema_migrations table exists.
 *   2. Scan *.sql files lexicographically.
 *   3. For each file whose basename (without .sql) is not yet in
 *      schema_migrations, execute the SQL and record the version.
 *
 * Uses `conn` directly (caller supplies a MySQL connection).
 * Returns 1 on success, 0 on failure. */
int migrate_run(MYSQL *conn, const char *migrations_dir);

#endif /* INFRA_MIGRATE_H */
