# Tests Analysis — paired counterfactual design rationale

Verifier-side document. Not visible to agents.

## 1. Information provided by instruction.md and the public spec

The agent receives: the three-snapshot collection format (both manifest forms), the four
artifact classes and which browser evidence feeds each, snapshot ordering rules,
`complete_artifacts` census semantics, the five final states, confirmed-absence semantics
(missing + complete class = absent; missing + incomplete class = unknown), first-observation
semantics (observation boundary, not creation), reinstall precedence, SHA-256 body identity
with dedup, website-SW exclusion, profile-key entity identity, cached != executed, timestamp
priority and null-time honesty, the full report schema (including the evidence fact
vocabulary and uncertainty reasons), path-traversal-safe on-disk correlation, downgrade
rules, and the opt-in CLI contract.

## 2. Theoretical pass path

Clone/inspect Hindsight at the pinned SHA -> read how `Chrome` parses Extensions/,
Secure Preferences, and Service Worker/Database + ScriptCache -> run those parsers per
snapshot -> normalize into three-valued presence -> apply census completeness -> key
entities by (profile_key, extension_id) -> dedupe revisions by body SHA-256 -> establish
removal boundaries between adjacent snapshots -> prove/distrove post-removal revisions
against per-snapshot cache completeness -> precedence: conflict > reinstall > boundary >
active > unknown -> emit provenance + uncertainty -> wire the opt-in CLI flag ->
upstream regression stays green.

## 3. Checkpoint justification (every hidden check derivable from the public spec)

| Case | Flipped fact (vs its pair) | Expected | Spec basis |
| :--- | :--- | :--- | :--- |
| P1_active | — | ACTIVE + consistent | §6/§10: present, no boundary, disk body == cache body |
| P2_residual | — | RESIDUAL_RUNTIME | §6: adjacent present->absent boundary; no new revision |
| P3_post_removal | — | POST_REMOVAL_CHANGE | §6: boundary + BBB provably absent at S1 (cache complete) |
| P4_reinstalled | — | REINSTALLED | §6: confirmed absence then confirmed presence; precedence |
| P5_indeterminate | — | INDETERMINATE | §6: gap right after last confirmed presence breaks the boundary |
| H2B_cache_incomplete | S1 script_cache flag | INDETERMINATE | §6.3: BBB absence at S1 unconfirmable |
| H4A_duplicate_bodies | two cache entries, same body | RESIDUAL, 1 revision | §3.3 dedup by body SHA-256 |
| H4B_distinct_bodies | two cache entries, distinct bodies | POST_REMOVAL, 2 revisions | §3.3 identity is body, not URL |
| H5B_conflict | inventory says absent, disk says present | INDETERMINATE + conflicting_evidence | §3.1/§9: conflict != majority vote |
| H13_website_sw_inert | adds https://example.com SW | identical to P2, no extra entity | §3.4 |
| H15_path_traversal | manifest points outside root | ACTIVE + runtime_consistency unknown; canary hash absent | §8 |
| H16_malformed_inventory | truncated prefs file | INDETERMINATE, no crash | §4/§9: unparseable class behaves as incomplete |
| H17_profile_isolation | same id, second profile_key | two independent entities | §2 entity = (profile_key, extension_id) |
| H18_missing_middle | collection has only s0, s2 | RESIDUAL_RUNTIME with transition s0->s2 | §5/§6: BBB first seen AT FA — unattributable to post-removal creation; §6.3 fails |
| H22_multi_version_ambiguous | two on-disk version dirs | ACTIVE + runtime_consistency unknown | §8: ambiguous active version |
| H23_disabled_extension | census record state=disabled | ACTIVE + consistent | §3.1: presence is install, not enabled |
| H24_mid_conflict_still_active | complete inventory/disk conflict at s1 | ACTIVE + conflicting_evidence recorded | §9: conflict degrades only dependent conclusions |
| H25_orphan_bodies | ScriptCache present, registration records absent | INDETERMINATE + incomplete_acquisition | §3.3: unscope-linked bodies are not entity evidence |
| H19_cache_complete_empty | S1 cache complete but empty | POST_REMOVAL (not INDETERMINATE) | §3.3/§4: complete census confirms absence |
| H20_active_divergent | disk body != cached body | ACTIVE + divergent | §8 |
| H21_update_in_place | revision changes, never removed | ACTIVE, 2 revisions, no transition | §10 state list: update is not post-removal change |

Paired counterfactuals flip exactly one documented field; no hidden rule is introduced.
Property checks: information monotonicity (P3>=H2B, P2>=P5, P2>=H16) and
irrelevant-evidence invariance (P2 == H13) are direct consequences of §9 and §3.4.

Note on §6 terminology (rev 2): the removal boundary is anchored by two snapshots —
LP (last confirmed presence) and FA (first confirmed absence). A revision first observed
at FA is unattributable to post-removal creation (§5), which is why H18 downgrades to
RESIDUAL_RUNTIME instead of POST_REMOVAL_CHANGE.

## 4. Why agent-authored self-tests do not catch these failures

- If the model encodes missing == absent, its own tests assert exactly that -> green on its
  fixtures -> P5/H16 hidden pair fails.
- If it encodes first observed == created, its fixtures use fully complete snapshots ->
  green -> H2B/H19 fail.
- If it encodes same id == same runtime, its fixtures never uninstall -> green -> P4/H17
  fail.
- If it encodes cache presence == execution, its tests only check cache presence -> green ->
  the execution-claims ban fails it.
- If it encodes majority vote, its fixtures never disagree -> green -> H5B fails.


## 5. Tier-2 calibration note (specimen-derived semantics)

The interpretation rules are no longer stated in the public spec; they are normative in
`/task_docs/specimens/` — 19 specimen collections with ground-truth reports produced by the
reference implementation. Specimen -> hidden-case derivation map:

| Specimen demonstrates | Hidden checks that generalize it |
| :--- | :--- |
| SP01 live runtime, consistent | P1_active |
| SP02 removal boundary + residual | P2_residual |
| SP03 census gap after last presence | P5_indeterminate, H16 (with SP14 corruption) |
| SP04 distinct revision after FA | P3_post_removal, H19 (complete-empty variant SP11) |
| SP05 census gap on script_cache | H2B_cache_incomplete |
| SP06 reappearance precedence | P4_reinstalled |
| SP07 conflict != majority | H5B_conflict |
| SP08 body identity / dedup | H4A_duplicate_bodies, H4B_distinct_bodies |
| SP09 website worker inert | H13_website_sw_inert |
| SP10 disabled != uninstalled | H23_disabled_extension |
| SP11 complete-but-empty census | H19_cache_complete_empty |
| SP12 traversal-safe correlation | H15_path_traversal |
| SP13 unlinked bodies unattributable | H25_orphan_bodies |
| SP14 corrupt census no-crash | H16_malformed_inventory |
| SP15 profile isolation | H17_profile_isolation |
| SP16 new revision AT FA unattributable | H18_missing_middle |
| SP17 scoped conflict degradation | H24_mid_conflict_still_active |
| SP18 divergent bodies | H20_active_divergent |
| SP19 multi-version ambiguity | H22_multi_version_ambiguous |
| SP20 tampered record corroborated | H28_tampered_but_corroborated |
| SP21 tampered record, no corroboration | H26_tampered_removal_census |
| SP22 seed mismatch flags all records | H27_wrong_seed |

Hidden cases use different identifiers, payloads, snapshot counts and shapes, so every
check requires generalization from the specimen set rather than lookup.
