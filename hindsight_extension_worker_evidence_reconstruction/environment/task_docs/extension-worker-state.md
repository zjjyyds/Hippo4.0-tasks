# Chromium Extension Service Worker Evidence Reconstruction — Interface Specification

## 0. About this specification and the reference specimens

This document defines the **interface contract**: the collection manifest format, the four
evidence classes, the five disposition states, the machine-readable report, and the
non-negotiable engineering constraints.

It deliberately does **not** define the forensic interpretation rules — i.e. what a parsed
record, a missing record, or a conflict actually entitles the analysis to conclude. Those
rules are normative in the **reference specimen archive**:

    /task_docs/specimens/

The archive holds specimen forensic collections, each accompanied by the ground-truth
report (`ground_truth_report.json`) that a correct analysis must produce for it. The
specimen set was assembled from production devices and covers every interpretation rule —
positively and negatively. The acceptance suite grades against unseen collections produced
by the same acquisition toolchain: every rule exercised there is demonstrated somewhere in
the specimen archive, and conclusions the specimens do not support must be downgraded, not
guessed.

Three principles govern everything (the specimens show how they are applied):

1. Findings must distinguish confirmed absence from evidence that was unavailable or
   incompletely collected.
2. An observation boundary is not an event boundary: observing something for the first time
   at a snapshot does not by itself establish when it came into existence.
3. The identity of an entity is not the identity of its lifecycle: the same identifier
   reappearing does not by itself establish continuity, and evidence that conflicts is
   preserved, never voted away.

---

## 1. Scope

A forensic acquisition system captured the same Chromium profile at several points in time
("snapshots"). Each snapshot is a Chromium profile directory collected the way browser
forensics tools normally collect them. The analysis must determine, for every extension
Service Worker runtime that appears anywhere in the collection, what the surviving evidence
supports about its current disposition.

---

## 2. Collection manifest

The input is a *collection root* directory containing `collection.json` and a `snapshots/`
tree. `collection.json` describes what was collected and how completely.

Single-profile form:

```json
{
  "schema_version": 1,
  "profile_key": "host01/user01/chrome/default",
  "snapshots": [
    {
      "id": "s0",
      "captured_at": "2026-08-01T10:00:00Z",
      "path": "snapshots/s0/Default",
      "complete_artifacts": [
        "extension_inventory", "extension_disk",
        "service_worker", "script_cache"
      ]
    }
  ],
  "integrity_seed": "<64-hex acquisition seed>"
}
```

Multi-profile form (one collection holding several profiles):

```json
{
  "schema_version": 1,
  "profiles": [
    {
      "profile_key": "host01/user01/chrome/default",
      "snapshots": [ /* snapshot objects as above */ ]
    }
  ]
}
```

- `profile_key` identifies the logical profile across the collection.
- `integrity_seed` (optional; per profile in the multi-profile form) is the
  acquisition-derived seed material for census record integrity metadata. Census
  records may carry such metadata. Whether and how it affects the findings is
  defined by the specimen archive.
- `snapshots` array order is the capture order (older first). Snapshot ordering is by this
  array — not by `captured_at` parsing and not by `id` strings.
- `captured_at` is the acquisition time. It is metadata about the acquisition, not evidence
  about when events inside the profile happened.

### 2.1 Artifact classes

`complete_artifacts` lists the evidence classes that the acquisition tool fully acquired for
that snapshot. Four classes exist:

| Class | Evidence it carries |
| :--- | :--- |
| `extension_inventory` | The profile's extension-install census as recorded by the browser |
| `extension_disk` | The on-disk installed-extension tree |
| `service_worker` | The browser's service-worker registration records and their resources |
| `script_cache` | The browser's cached service-worker script bodies |

A class not listed for a snapshot was **not completely acquired** for that snapshot. This
covers every flavor of partial acquisition: data not collected, collection interrupted, or
collected data that could not be parsed in full.

Which browser artifacts realize each class is defined by Hindsight's existing parsing
behavior; the analysis must reuse that behavior (see the task instruction) rather than
re-derive it. A class absent from a snapshot's directory tree, present but unreadable, or
present but only partially parseable all behave the same way: not completely acquired.

---

## 3. Disposition states

Every extension runtime entity observed anywhere in a collection receives exactly one
`current_state`:

`ACTIVE` · `RESIDUAL_RUNTIME` · `POST_REMOVAL_CHANGE` · `REINSTALLED` · `INDETERMINATE`

The state names describe an analyst's disposition of a worker runtime relative to the
extension's lifecycle as the evidence supports it. The conditions under which each state is
supported — and when the analysis must downgrade to `INDETERMINATE` — are defined by the
specimen archive (§0). `INDETERMINATE` entries must explain themselves through the
`uncertainty` field (§5); a state that the evidence does not support must not be emitted.

Additionally each entity carries `runtime_consistency` ∈ {`consistent`, `divergent`,
`unknown`}, comparing an installed extension's on-disk worker body against the observed
cached revisions when that comparison can be performed safely. Safety rule: the manifest-
declared worker path comes from forensic evidence and is not trusted — it must be resolved
strictly inside the extension root (the directory containing that `manifest.json`); anything
resolving outside it must not be read.

---

## 4. Robustness and safety constraints

- Malformed or truncated artifacts must not crash the analysis; an unparseable class behaves
  like an incompletely acquired one.
- The analysis must not read files outside the boundaries defined in §3.
- No network access. No execution of extension or worker JavaScript.
- The capability is opt-in (§6). Without it, Hindsight's behavior and serialized output are
  exactly as before.

---

## 5. Report schema

The report is a JSON document written to the path given on the command line. Top level:

```json
{
  "schema_version": 1,
  "profiles": [
    {
      "profile_key": "host01/user01/chrome/default",
      "extensions": [
        {
          "extension_id": "abcdefghijklmnopabcdefghijklmnop",
          "current_state": "RESIDUAL_RUNTIME",
          "runtime_consistency": "unknown",

          "snapshots": [
            {
              "snapshot_id": "s0",
              "extension_presence": "present",
              "registration_presence": "present",
              "script_revisions": ["sha256:<hex>"]
            }
          ],

          "revisions": [
            {
              "sha256": "sha256:<hex>",
              "first_observed_snapshot": "s0",
              "last_observed_snapshot": "s0"
            }
          ],

          "transitions": [
            {"type": "EXTENSION_REMOVED", "from_snapshot": "s0", "to_snapshot": "s1"}
          ],

          "evidence": [
            {
              "snapshot": "s1",
              "artifact": "extension_inventory",
              "fact": "extension_absent",
              "complete": true
            }
          ],

          "uncertainty": []
        }
      ]
    }
  ]
}
```

Field rules:

- `current_state` ∈ {`ACTIVE`, `RESIDUAL_RUNTIME`, `POST_REMOVAL_CHANGE`, `REINSTALLED`,
  `INDETERMINATE`}; `runtime_consistency` ∈ {`consistent`, `divergent`, `unknown`}.
- `snapshots[].extension_presence` / `registration_presence` ∈ {`present`, `absent`,
  `unknown`}; `script_revisions` lists the revisions observed in that snapshot as
  `sha256:<hex>`, sorted.
- `revisions[]` is the deduplicated set of script-body revisions observed for the entity
  across the collection, each with first and last observation snapshots.
- `transitions[].type` ∈ {`EXTENSION_REMOVED`, `EXTENSION_REAPPEARED`} with the snapshot ids
  of the endpoints; only snapshot ids that exist in the collection may appear.
- `evidence[]` records the facts the state relies on. Facts use exactly this vocabulary:
  `extension_present`, `extension_absent`, `extension_state_unknown`,
  `registration_present`, `registration_absent`, `registration_state_unknown`,
  `revision_observed`, `revisions_state_unknown`,
  `disk_worker_consistent`, `disk_worker_divergent`, `disk_worker_unverifiable`,
  `census_record_untrusted`.
- `uncertainty[]` entries carry `snapshot` (when scoped), `artifact`, and `reason` ∈
  {`incomplete_acquisition`, `conflicting_evidence`, `census_integrity_unverified`}.
- Extensions sorted by `extension_id`; profiles by `profile_key`; snapshot entries in
  collection order.
- The report must not contain fields beyond this schema, and no field may assert that a
  revision was executed, activated, or run.

The ground-truth reports in the specimen archive are authoritative examples of this schema.

---

## 6. Invocation

The analysis is opt-in. With the flag absent, Hindsight behaves exactly as before. With the
flag present, Hindsight reads the collection root, reconstructs the per-profile state and
writes the JSON report; the regular spreadsheet/JSONL outputs of a normal single-profile run
are not part of this mode:

```
python3 hindsight.py -i <collection_root> --extension-worker-report <report.json>
```
