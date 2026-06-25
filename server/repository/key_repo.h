#ifndef REPOSITORY_KEY_REPO_H
#define REPOSITORY_KEY_REPO_H

/* â”€â”€ User identity key record â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/* Upsert the identity key record for a user (Ed25519 identity_pk, self-signature,
 * and the master-key-encrypted identity secret backup).
 * Optional fields may be NULL or "".  Returns 1 on success, 0 on error. */
int key_upload_user(int uid,
                    const char *identity_pk_b64, const char *identity_sig_b64,
                    const char *identity_sk_enc_b64);

/* Fetch the owner's own identity key record (including the encrypted secret backup).
 * Returns 1 on success, 0 if not found. */
int key_get_my_keys(int uid,
                    char *identity_pk,  int ipk_len,
                    char *identity_sig, int isig_len,
                    char *identity_sk_enc, int isk_len);

/* Identity versioning */

/* Atomically increment identity_version for uid.
 * Returns the new version (>= 1) on success, -1 on error. */
int key_bump_identity_version(int uid);

/* Get the current identity_version for uid.
 * Returns version >= 0 on success, -1 if not found. */
int key_get_identity_version(int uid);

/* Fetch the currently stored identity public key and version.
 * Returns 1 if an identity key exists, 0 otherwise. */
int key_get_current_identity(int uid,
                             char *identity_pk, int identity_pk_len,
                             int *version_out);

/* Append an identity transparency event if this (user, version) row is absent.
 * event_type must be "initial" or "rotation".
 * Returns 1 on success, 0 on error. */
int key_append_identity_log(int uid, int identity_version,
                            const char *identity_pk,
                            const char *device_id_hash,
                            const char *device_label,
                            const char *event_type,
                            char *leaf_hash_out, int leaf_hash_len);

/* â”€â”€ SecChat PQXDH bundles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

typedef struct PqxdhBundleRecord {
    char identity_pk[256];
    int  curve_spk_id;
    char curve_spk[256];
    char curve_spk_sig[256];
    int  pq_spk_id;
    char pq_kem_alg[32];
    char pq_spk[4096];
    char pq_spk_sig[256];
    int  curve_otk_id;
    char curve_otk[256];
    char curve_otk_sig[256];
    int  pq_otk_id;
    char pq_otk_alg[32];
    char pq_otk[4096];
    char pq_otk_sig[256];
    int  curve_pool;
    int  pq_pool;
} PqxdhBundleRecord;

int key_pqxdh_upload_bundle(int uid,
                         const char *identity_pk,
                         int curve_spk_id,
                         const char *curve_spk,
                         const char *curve_spk_sig,
                         int pq_spk_id,
                         const char *pq_kem_alg,
                         const char *pq_spk,
                         const char *pq_spk_sig);

int key_pqxdh_upload_curve_otk(int uid, int key_id,
                            const char *public_key,
                            const char *signature);

int key_pqxdh_upload_pq_otk(int uid, int key_id, const char *kem_alg,
                         const char *public_key,
                         const char *signature);

int key_pqxdh_get_status(int uid, int *has_bundle_out,
                      int *curve_count_out, int *pq_count_out);

int key_pqxdh_get_bundle_consuming(int target_uid, PqxdhBundleRecord *out);

#endif /* REPOSITORY_KEY_REPO_H */
