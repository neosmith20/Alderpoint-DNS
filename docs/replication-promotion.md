# Manual Replica Promotion

Alderpoint DNS replication is intentionally one-way. A replica can be promoted only
by an administrator after confirming that the old primary is no longer the
source of truth.

Recommended lab procedure:

1. Confirm plain DNS still answers on the replica.
2. Run a manual drift check from the replica's Replication page.
3. If the replica is in sync, switch its role from `replica` to `primary`.
4. Generate new enrollment tokens for any downstream replicas.
5. Update clients or network routing outside Alderpoint DNS only after the new
   primary's DNS and web health checks pass.

Automatic failover and bidirectional conflict resolution are not implemented.
