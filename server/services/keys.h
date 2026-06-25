#ifndef SERVICES_KEYS_H
#define SERVICES_KEYS_H

/*
 * services/keys.h — key management bounded context
 *
 * keys_dispatch() handles:
 *   upload_keys                 — upload current Ed25519 identity record
 *   get_my_keys                 — fetch own identity record (public + enc secret)
 *   rotate_identity             — rotate identity key, bump version,
 *                                 notify DM partners with safety_number_changed
 *
 * Returns 1 if the type was handled, 0 if not recognised.
 */
int keys_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_KEYS_H */
