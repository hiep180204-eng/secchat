/*
 * domain/test_domain_unit.c — Self-contained domain layer unit tests.
 *
 * No database, no network, no OpenSSL — pure standard C only.
 *
 * Compile (from server/ directory):
 *   gcc -I. -Idomain -Wall -Wextra -o /tmp/test_domain \
 *       domain/test_domain_unit.c domain/validation.c
 *
 * Run:
 *   /tmp/test_domain
 *   echo $?   # 0 = all pass, 1 = at least one failure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "validation.h"
#include "entities.h"
#include "caller_context.h"

/* ── Tiny test framework ──────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define CHECK(name, expr) do {                                  \
    if (expr) {                                                  \
        printf("  PASS  %s\n", name);                           \
        g_pass++;                                                \
    } else {                                                     \
        printf("  FAIL  %s\n", name);                           \
        g_fail++;                                                \
    }                                                            \
} while (0)

/* ── validation: username ─────────────────────────────────────────────────── */

static void test_username(void)
{
    printf("\n=== domain/validate_username ===\n");

    CHECK("valid 'alice'",          domain_validate_username("alice"));
    CHECK("valid 'user_123'",       domain_validate_username("user_123"));
    CHECK("valid 'ABC'",            domain_validate_username("ABC"));
    CHECK("valid 3-char min 'abc'", domain_validate_username("abc"));

    CHECK("invalid NULL",            !domain_validate_username(NULL));
    CHECK("invalid empty ''",        !domain_validate_username(""));
    CHECK("invalid too short 'ab'",  !domain_validate_username("ab"));
    CHECK("invalid space 'ab cd'",   !domain_validate_username("ab cd"));
    CHECK("invalid hyphen 'ab-c'",   !domain_validate_username("ab-c"));
    CHECK("invalid at-sign 'a@b'",   !domain_validate_username("a@b"));
    CHECK("invalid dot 'a.b'",       !domain_validate_username("a.b"));

    /* Boundary: exactly 63 chars (valid), 64 chars (invalid) */
    {
        char name63[65], name64[66];
        memset(name63, 'a', 63); name63[63] = '\0';
        memset(name64, 'a', 64); name64[64] = '\0';
        CHECK("valid 63-char name",   domain_validate_username(name63));
        CHECK("invalid 64-char name", !domain_validate_username(name64));
    }
}

/* ── validation: email ────────────────────────────────────────────────────── */

static void test_email(void)
{
    printf("\n=== domain/validate_email ===\n");

    /* Valid emails */
    CHECK("valid 'user@example.com'",   domain_validate_email("user@example.com"));
    CHECK("valid 'a@b.io'",             domain_validate_email("a@b.io"));
    CHECK("valid 'x+y@mail.org'",       domain_validate_email("x+y@mail.org"));

    /* Empty / NULL → valid (email is optional) */
    CHECK("valid NULL (optional)",      domain_validate_email(NULL));
    CHECK("valid empty '' (optional)",  domain_validate_email(""));

    /* Invalid emails */
    CHECK("invalid no @ 'userexample'",     !domain_validate_email("userexample"));
    CHECK("invalid @ first '@example.com'", !domain_validate_email("@example.com"));
    CHECK("invalid no dot 'user@example'",  !domain_validate_email("user@example"));

    /* Boundary: 254-char max */
    {
        char long_email[300];
        memset(long_email, 'a', 250);
        memcpy(long_email + 250, "@b.io", 6);   /* 255 chars total */
        CHECK("invalid 255-char email", !domain_validate_email(long_email));
    }
}

/* ── validation: group name ───────────────────────────────────────────────── */

static void test_group_name(void)
{
    printf("\n=== domain/validate_group_name ===\n");

    CHECK("valid 'My Group'",          domain_validate_group_name("My Group"));
    CHECK("valid single char 'X'",     domain_validate_group_name("X"));
    CHECK("valid unicode bytes",        domain_validate_group_name("\xc3\xa9l\xc3\xa8ve")); /* "eleve" with accents */

    CHECK("invalid NULL",              !domain_validate_group_name(NULL));
    CHECK("invalid empty ''",          !domain_validate_group_name(""));

    /* 100-char boundary */
    {
        char n100[102], n101[103];
        memset(n100, 'x', 100); n100[100] = '\0';
        memset(n101, 'x', 101); n101[101] = '\0';
        CHECK("valid 100-char name",   domain_validate_group_name(n100));
        CHECK("invalid 101-char name", !domain_validate_group_name(n101));
    }
}

/* ── validation: message body ─────────────────────────────────────────────── */

static void test_message_body(void)
{
    printf("\n=== domain/validate_message_body ===\n");

    CHECK("valid 'hello'",              domain_validate_message_body("hello", 4096));
    CHECK("valid single char 'x'",      domain_validate_message_body("x", 1));
    CHECK("valid exactly max_len",      domain_validate_message_body("abcde", 5));

    CHECK("invalid NULL",               !domain_validate_message_body(NULL, 4096));
    CHECK("invalid empty ''",           !domain_validate_message_body("", 4096));
    CHECK("invalid over max_len",       !domain_validate_message_body("abcdef", 5));

    /* Zero max_len → nothing fits */
    CHECK("invalid max_len=0",          !domain_validate_message_body("a", 0));
}

/* ── validation: role ─────────────────────────────────────────────────────── */

static void test_role(void)
{
    printf("\n=== domain/validate_role ===\n");

    CHECK("valid 'admin'",    domain_validate_role("admin"));
    CHECK("valid 'member'",   domain_validate_role("member"));

    CHECK("invalid NULL",     !domain_validate_role(NULL));
    CHECK("invalid ''",       !domain_validate_role(""));
    CHECK("invalid 'owner'",  !domain_validate_role("owner"));
    CHECK("invalid 'ADMIN'",  !domain_validate_role("ADMIN"));
    CHECK("invalid 'mod'",    !domain_validate_role("mod"));
}

/* ── validation: pwhash ───────────────────────────────────────────────────── */

static void test_pwhash(void)
{
    printf("\n=== domain/validate_pwhash ===\n");

    const char *valid = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
    const char *upper = "A665A45920422F9D417E4867EFDC4FB8A04A1F3FFF1FA07E998E86F7F7A27AE3";

    CHECK("valid lowercase hex (64 chars)", domain_validate_pwhash(valid));
    CHECK("valid uppercase hex (64 chars)", domain_validate_pwhash(upper));

    CHECK("invalid NULL",                   !domain_validate_pwhash(NULL));
    CHECK("invalid 63-char hex",
          !domain_validate_pwhash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27a"));
    CHECK("invalid 65-char hex",
          !domain_validate_pwhash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3f"));
    CHECK("invalid non-hex 'g...' char",
          !domain_validate_pwhash("g665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"));
    CHECK("invalid empty ''",               !domain_validate_pwhash(""));
}

/* ── entities: UserEntity ─────────────────────────────────────────────────── */

static void test_user_entity(void)
{
    printf("\n=== domain/UserEntity ===\n");

    UserEntity u;
    memset(&u, 0, sizeof(u));
    u.id = 42;
    strncpy(u.username,     "alice",        DOMAIN_USERNAME_MAX - 1);
    strncpy(u.display_name, "Alice Nguyen", DOMAIN_DISPLAYNAME_MAX - 1);
    strncpy(u.status,       "online",       DOMAIN_STATUS_MAX - 1);

    CHECK("id field",           u.id == 42);
    CHECK("username field",     strcmp(u.username, "alice") == 0);
    CHECK("display_name field", strcmp(u.display_name, "Alice Nguyen") == 0);
    CHECK("status field",       strcmp(u.status, "online") == 0);

    /* Copy by value */
    UserEntity u2 = u;
    u2.id = 99;
    CHECK("copy is independent (original id unchanged)", u.id == 42);
    CHECK("copy id set",                                 u2.id == 99);
}

/* ── entities: GroupEntity ────────────────────────────────────────────────── */

static void test_group_entity(void)
{
    printf("\n=== domain/GroupEntity ===\n");

    GroupEntity g;
    memset(&g, 0, sizeof(g));
    g.id = 123;
    strncpy(g.name,        "Dev Chat",  DOMAIN_GROUP_NAME_MAX - 1);
    strncpy(g.description, "test desc", DOMAIN_DESC_MAX - 1);
    g.creator_id   = 42;
    g.is_disbanded = 0;

    CHECK("id field",           g.id == 123);
    CHECK("name field",         strcmp(g.name, "Dev Chat") == 0);
    CHECK("description field",  strcmp(g.description, "test desc") == 0);
    CHECK("creator_id field",   g.creator_id == 42);
    CHECK("not disbanded",      !g.is_disbanded);
}

/* ── entities: MessageEntity ──────────────────────────────────────────────── */

static void test_message_entity(void)
{
    printf("\n=== domain/MessageEntity ===\n");

    MessageEntity m;
    memset(&m, 0, sizeof(m));
    m.id         = 999;
    m.conv_id    = 1;
    m.sender_id  = 42;
    strncpy(m.body, "hello world", DOMAIN_BODY_MAX - 1);
    m.sent_at    = 1700000000;
    m.is_deleted = 0;

    CHECK("id field",         m.id == 999);
    CHECK("conv_id field",    m.conv_id == 1);
    CHECK("sender_id field",  m.sender_id == 42);
    CHECK("body field",       strcmp(m.body, "hello world") == 0);
    CHECK("not deleted",      !m.is_deleted);
    CHECK("no reply_to",      m.reply_to_id == 0);
    CHECK("no forwarded",     m.forwarded_from == 0);
}

/* ── CallerContext: synthetic (no server deps) ────────────────────────────── */

static void test_caller_context(void)
{
    printf("\n=== domain/CallerContext (synthetic) ===\n");

    CallerContext c = caller_synthetic(7, "bob");
    CHECK("uid set",             c.uid == 7);
    CHECK("username set",        strcmp(c.username, "bob") == 0);
    CHECK("idx is -1",           c.idx == -1);
    CHECK("caller_ok is true",   caller_ok(&c));

    /* Unauthenticated */
    CallerContext anon = caller_synthetic(-1, "");
    CHECK("anon uid == -1",       anon.uid == -1);
    CHECK("caller_ok is false",   !caller_ok(&anon));

    /* Username truncation at CALLER_USERNAME_MAX-1 */
    {
        char long_uname[200];
        memset(long_uname, 'z', 199); long_uname[199] = '\0';
        CallerContext lc = caller_synthetic(1, long_uname);
        CHECK("username capped at max-1",
              strlen(lc.username) == CALLER_USERNAME_MAX - 1);
    }
}

/* ── entry point ──────────────────────────────────────────────────────────── */

int main(void)
{
    printf("\n===========================================\n");
    printf(  "  SecChat domain unit tests\n");
    printf(  "===========================================\n");

    test_username();
    test_email();
    test_group_name();
    test_message_body();
    test_role();
    test_pwhash();
    test_user_entity();
    test_group_entity();
    test_message_entity();
    test_caller_context();

    printf("\n==========================================\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("==========================================\n\n");

    return (g_fail > 0) ? 1 : 0;
}
