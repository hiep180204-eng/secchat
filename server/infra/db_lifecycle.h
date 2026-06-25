#ifndef INFRA_DB_LIFECYCLE_H
#define INFRA_DB_LIFECYCLE_H

/* Connect to MySQL (retries up to 60 times), run migrations, init pool. */
int  db_connect(void);

/* Close the MySQL singleton connection. */
void db_close(void);

#endif /* INFRA_DB_LIFECYCLE_H */
