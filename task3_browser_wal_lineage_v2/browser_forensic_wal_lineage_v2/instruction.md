# Browser forensic: evidence lineage across SQLite WAL acquisitions

Extend the pinned `SecurityRonin/browser-forensic` checkout with `browser_forensic_core::wal_lineage::inspect_wal_lineage(root: &Path) -> std::io::Result<WalLineageReport>`. The starter provides the public types and an empty implementation.

`root/manifest.json` contains `captures: [{"id": string, "order": integer, "db": relative_path}]`. Entries may be unordered. Each `db` is a SQLite main-file snapshot; a sidecar may exist at `<db>-wal`. An acquisition contains the paired on-disk bytes at one observation point. The `order` field defines observation ordering; it does not by itself prove continuity.

Return a `WalLineageReport` with:

- `captures`: ordered by `order`. Each contains `id`, `base_sha256`, `commits`, and `terminal_sha256`. `commits` consists of `end_frame` (1-based), `database_pages`, and `sha256` (64 lowercase hex characters). Each digest identifies the complete physical SQLite page image at a valid WAL commit boundary. `base_sha256` describes the acquired main-file bytes; `terminal_sha256` is the last valid committed image, or the main-file digest when there is no valid commit.
- `links`: one entry for each ordered pair of acquisitions, ordered by first acquisition then second. Each contains `from`, `to`, `relation` and `anchors` (a list of 1-based WAL commit frames witnessing a matching prior committed image, empty for other relations). Use the most specific supported relation: `identical_evidence` (both acquired files identical), `shared_wal_prefix` (the earlier validated committed WAL history is physically included in the later acquisition on the same base), `checkpoint_compatible` (a validated earlier committed image equals the later main-file image; list every matching prior commit in `anchors`), `equal_result_only` (the terminal images agree, without a stronger witness), or `unproven` (none of these claims are established). Relations denote evidence compatibility, not proof of a shared real-world event or process.

Do not report invalid, torn, uncommitted or unverifiable WAL data as committed. Preserve valid committed prefixes when later data is damaged. Missing sidecars are allowed; missing/invalid SQLite main files are errors. Evidence files must remain unchanged. Existing `browser-forensic-core` behavior must remain compatible.

Only final behavior and regressions are graded. Implementation and debugging methods are unrestricted. The environment is offline and contains the upstream pinned dependencies.
