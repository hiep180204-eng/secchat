#ifndef DOMAIN_ENTITIES_H
#define DOMAIN_ENTITIES_H

/*
 * domain/entities.h — Immutable value objects for the SecChat domain.
 *
 * These structs carry pure data; they contain no pointers to heap memory
 * and no references to database state.  They are safe to copy, compare,
 * and pass by value across layer boundaries.
 *
 * The constants below shadow clients.h's USERNAME_LEN etc. intentionally:
 * the domain layer must not include transport headers.
 */

#include <stddef.h>
#include <time.h>

/* ── Domain constants ─────────────────────────────────────────────────────── */

#define DOMAIN_USERNAME_MAX    64     /* max username length incl. NUL */
#define DOMAIN_DISPLAYNAME_MAX 256    /* max display_name length incl. NUL */
#define DOMAIN_STATUS_MAX      32     /* "online" / "offline" / "away" + NUL */
#define DOMAIN_ROLE_MAX        16     /* "admin" / "member" + NUL */
#define DOMAIN_GROUP_NAME_MAX  101    /* 100 chars + NUL */
#define DOMAIN_DESC_MAX        1025   /* 1024 chars + NUL */
#define DOMAIN_BODY_MAX        4097   /* 4096 chars + NUL */

/* ── UserEntity ───────────────────────────────────────────────────────────── */

/* Snapshot of a user's identity (no live DB cursor). */
typedef struct {
    int  id;
    char username    [DOMAIN_USERNAME_MAX];
    char display_name[DOMAIN_DISPLAYNAME_MAX];
    char status      [DOMAIN_STATUS_MAX];   /* "online" | "offline" | "away" */
} UserEntity;

/* ── GroupEntity ──────────────────────────────────────────────────────────── */

/* Snapshot of a group conversation's metadata. */
typedef struct {
    long long id;
    char      name       [DOMAIN_GROUP_NAME_MAX];
    char      description[DOMAIN_DESC_MAX];
    int       creator_id;
    int       is_disbanded;
} GroupEntity;

/* ── MemberEntry ──────────────────────────────────────────────────────────── */

/* One member slot inside a GroupEntity's member list. */
typedef struct {
    int  user_id;
    char username[DOMAIN_USERNAME_MAX];
    char role    [DOMAIN_ROLE_MAX];     /* "admin" | "member" */
} MemberEntry;

/* ── MessageEntity ────────────────────────────────────────────────────────── */

/* Immutable representation of a stored message. */
typedef struct {
    long long id;
    long long conv_id;
    int       sender_id;
    char      body          [DOMAIN_BODY_MAX];
    time_t    sent_at;
    int       is_deleted;
    long long reply_to_id;      /* 0 if not a reply */
    long long forwarded_from;   /* 0 if not a forward */
} MessageEntity;

#endif /* DOMAIN_ENTITIES_H */
