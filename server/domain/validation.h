#ifndef DOMAIN_VALIDATION_H
#define DOMAIN_VALIDATION_H

/*
 * domain/validation.h — Pure, stateless validation functions for business rules.
 *
 * No database access, no network, no system state.
 * Suitable for direct unit testing.
 *
 * These are the canonical validation rules for the SecChat domain.
 * auth.c delegates to these functions so validation logic lives in one place.
 */

#include <stddef.h>

/* Returns 1 if the username is valid:
 *   - 3 to 63 characters
 *   - Letters, digits, and underscore only
 * Returns 0 otherwise (including NULL). */
int domain_validate_username(const char *username);

/* Returns 1 if the email is syntactically valid OR empty (email is optional):
 *   - Non-empty: must contain '@' with a non-empty local part, and a dot after '@'
 *   - Empty string or NULL: returns 1 (email is optional at registration)
 *   - Max 254 characters (RFC 5321)
 * Returns 0 if non-empty but malformed. */
int domain_validate_email(const char *email);

/* Returns 1 if the group name is valid:
 *   - 1 to 100 characters (any content)
 * Returns 0 for empty or NULL. */
int domain_validate_group_name(const char *name);

/* Returns 1 if the message body is valid:
 *   - Non-empty
 *   - Length <= max_len bytes
 * Returns 0 for empty, NULL, or oversized. */
int domain_validate_message_body(const char *body, size_t max_len);

/* Returns 1 if the role is a valid group role: "admin" or "member".
 * Returns 0 otherwise (including NULL or empty). */
int domain_validate_role(const char *role);

/* Returns 1 if the password hash is a valid 64-character hex string (SHA-256).
 * Returns 0 otherwise (including NULL, wrong length, or non-hex chars). */
int domain_validate_pwhash(const char *pwhash);

/* Returns 1 if the display name is valid:
 *   - Empty string or NULL: returns 1 (display name is optional)
 *   - Non-empty: 1 to 64 characters
 * Returns 0 if non-empty but longer than 64 chars. */
int domain_validate_display_name(const char *name);

/* Returns 1 if the bio text is valid:
 *   - Empty string or NULL: returns 1 (bio is optional)
 *   - Non-empty: up to 512 characters
 * Returns 0 if non-empty but longer than 512 chars. */
int domain_validate_bio(const char *bio);

/* Returns 1 if the emoji string is valid:
 *   - Non-empty, up to 32 bytes
 * Returns 0 for empty, NULL, or oversized. */
int domain_validate_emoji(const char *emoji);

/* Returns 1 if the message body carries a recognised SecChat S3 E2EE prefix:
 *   S3PQI:<b64-json> — DM initial hybrid PQXDH message
 *   S3DR:<b64-json>  — DM Double Ratchet message
 *   S3MLS:<b64-json> — group/control message
 * Returns 0 for plaintext, removed prefixes, or unrecognised prefixes.
 * Call after domain_validate_message_body() passes. */
int domain_validate_e2e_prefix(const char *body);

#endif /* DOMAIN_VALIDATION_H */
