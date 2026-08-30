# Portable backup schema provenance

`portable-backup.sql` is a byte-for-byte snapshot of:

- repository: `ORESoftware/k8s-libs-and-shared-defs`
- revision: `148229d17e0d58bc34e106fbe7fd6a4d9d0272fd`
- path: `pg-defs/schema/databases/cliptown/portable-backup.sql`
- SHA-256: `841e2914df5a14a675f746454d715929f7c2633d58343aa63fc519ac51a7faa7`

The shared-definitions repository remains authoritative. The snapshot lets an
unprivileged pull-request workflow verify the exact contract without a
cross-organization private-repository token. Updating it requires copying an
exact reviewed upstream revision, updating both pinned values in
`.github/workflows/portable-backup-contract.yml`, and proving DPM convergence
against PostgreSQL and CockroachDB.
