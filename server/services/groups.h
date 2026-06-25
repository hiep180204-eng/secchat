#ifndef SERVICES_GROUPS_H
#define SERVICES_GROUPS_H

/*
 * services/groups.h - group management bounded context.
 *
 * Group membership and metadata changes are a two-step MLS operation:
 *   prepare_group_change - validate policy and reserve a pending operation.
 *   apply_group_change   - persist OpenMLS Commit/Welcome/GroupInfo/control
 *                          bytes and only then update server metadata.
 *   get_mls_handshake    - replay stored MLS handshake/control artifacts.
 *   get_group_info       - fetch group metadata and member roles.
 *
 * Older direct mutation commands are handled only to return a precise error;
 * they no longer mutate group state.
 *
 * Returns 1 if the type was handled, 0 if not recognised.
 */
int groups_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_GROUPS_H */
