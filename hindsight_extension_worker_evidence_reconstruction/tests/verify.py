#!/usr/bin/env python3
"""Verifier for hindsight_extension_worker_evidence_reconstruction.

Usage: verify.py <fixtures_dir> <expected_dir> <reports_dir>

Semantics of the check (per the public spec, task_docs/extension-worker-state.md):
  - the opt-in CLI must have produced a parseable report for every case;
  - per-case expected facts must hold (state, runtime_consistency, revisions,
    transitions, uncertainty reasons, entity isolation, path-safety);
  - information monotonicity: degrading evidence must never strengthen a state;
  - no execution claims anywhere in the report (cached != executed);
  - evidence facts use the documented vocabulary.
Internal class names, module layout and algorithms are NOT verified.
"""
import json
import os
import sys

FORBIDDEN_KEYS = {"executed", "activated", "ran", "execution", "executed_after_removal"}

FACT_VOCABULARY = {
    "extension_present", "extension_absent", "extension_state_unknown",
    "registration_present", "registration_absent", "registration_state_unknown",
    "revision_observed", "revisions_state_unknown",
    "disk_worker_consistent", "disk_worker_divergent", "disk_worker_unverifiable",
    "census_record_untrusted",
}

STATE_STRENGTH = {"INDETERMINATE": 0, "RESIDUAL_RUNTIME": 1, "ACTIVE": 2,
                  "POST_REMOVAL_CHANGE": 2, "REINSTALLED": 2}

# Counterfactual pairs: (strong-evidence case, degraded-evidence case).
# Degrading evidence may downgrade the state but must never strengthen it.
MONOTONICITY_PAIRS = [
    ("P3_post_removal", "H2B_cache_incomplete"),
    ("P2_residual", "P5_indeterminate"),
    ("P2_residual", "H16_malformed_inventory"),
]

# Evidence-irrelevance pairs: adding unrelated website service workers must not
# change an unrelated extension's disposition.
IRRELEVANCE_PAIRS = [
    ("P2_residual", "H13_website_sw_inert"),
]


def fail(msg):
    print(f"[-] FAIL: {msg}")
    sys.exit(1)


def walk_keys(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from walk_keys(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_keys(item)


def walk_facts(obj):
    if isinstance(obj, dict):
        if "fact" in obj and isinstance(obj.get("fact"), str):
            yield obj["fact"]
        for value in obj.values():
            yield from walk_facts(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_facts(item)


def check_report_structure(report, case_id):
    if report.get("schema_version") != 1:
        fail(f"[{case_id}] report schema_version must be 1")
    if not isinstance(report.get("profiles"), list) or not report["profiles"]:
        fail(f"[{case_id}] report.profiles missing/empty")
    for profile in report["profiles"]:
        if not profile.get("profile_key") or not isinstance(profile.get("extensions"), list):
            fail(f"[{case_id}] malformed profile entry")


def check_no_execution_claims(report, case_id):
    keys = {k.lower() for k in walk_keys(report)}
    hits = keys & FORBIDDEN_KEYS
    if hits:
        fail(f"[{case_id}] execution claims present in report (cached != executed): {sorted(hits)}")


def check_fact_vocabulary(report, case_id):
    for fact in walk_facts(report):
        if fact not in FACT_VOCABULARY:
            fail(f"[{case_id}] unknown evidence fact: {fact!r}")


def check_transitions_reference_real_snapshots(case_dir, report, case_id):
    manifest = json.load(open(os.path.join(case_dir, "collection.json"), encoding="utf-8"))
    if "profiles" in manifest:
        ids = {s["id"] for p in manifest["profiles"] for s in p["snapshots"]}
    else:
        ids = {s["id"] for s in manifest["snapshots"]}
    for profile in report["profiles"]:
        for ext in profile["extensions"]:
            for t in ext.get("transitions", []):
                if t["from_snapshot"] not in ids or t["to_snapshot"] not in ids:
                    fail(f"[{case_id}] transition references non-existent snapshot: {t}")


def check_entity(exp, entry, case_id, profile_key):
    if exp.get("extension_id") and entry["extension_id"] != exp["extension_id"]:
        fail(f"[{case_id}] wrong extension_id {entry['extension_id']}")
    if entry["current_state"] != exp["state"]:
        fail(f"[{case_id}] {profile_key}: current_state {entry['current_state']} != {exp['state']}")
    if exp.get("consistency") and entry["runtime_consistency"] != exp["consistency"]:
        fail(f"[{case_id}] {profile_key}: runtime_consistency "
             f"{entry['runtime_consistency']} != {exp['consistency']}")

    if "revisions" in exp:
        got = [r["sha256"].split(":", 1)[-1][:8] for r in entry["revisions"]]
        got = [{"3c8b9a23": "AAA", "7d70da7d": "BBB"}.get(x, x) for x in got]
        if got != exp["revisions"]:
            fail(f"[{case_id}] revisions {got} != {exp['revisions']}")
    if "revisions_count" in exp and len(entry["revisions"]) != exp["revisions_count"]:
        fail(f"[{case_id}] revision count {len(entry['revisions'])} != {exp['revisions_count']}")

    if "transitions" in exp:
        got = [(t["type"], t["from_snapshot"], t["to_snapshot"]) for t in entry["transitions"]]
        want = [tuple(t) for t in exp["transitions"]]
        if got != want:
            fail(f"[{case_id}] transitions {got} != {want}")
    if "transition_count" in exp and len(entry["transitions"]) != exp["transition_count"]:
        fail(f"[{case_id}] transition count {len(entry['transitions'])} != {exp['transition_count']}")

    if "uncertainty" in exp:
        got = {(u.get("snapshot"), u["reason"]) for u in entry["uncertainty"]}
        want = {tuple(x) for x in exp["uncertainty"]}
        if not want <= got:
            fail(f"[{case_id}] uncertainty must explain: {sorted(want - got)}; got {sorted(got)}")

    if "forbidden_revision" in exp:
        blob = json.dumps(entry)
        if exp["forbidden_revision"] in blob:
            fail(f"[{case_id}] content outside the extension root was read and hashed "
                 f"(path traversal)")


def main(fixtures_dir, expected_dir, reports_dir):
    case_ids = sorted(os.listdir(fixtures_dir))
    reports = {}
    for case_id in case_ids:
        path = os.path.join(reports_dir, f"{case_id}.json")
        if not os.path.isfile(path):
            fail(f"[{case_id}] report missing (opt-in analysis did not run)")
        try:
            with open(path, encoding="utf-8") as handle:
                reports[case_id] = json.load(handle)
        except json.JSONDecodeError as exc:
            fail(f"[{case_id}] report is not valid JSON: {exc}")

    summary = []
    for case_id in case_ids:
        report = reports[case_id]
        expected = json.load(open(os.path.join(expected_dir, f"{case_id}.json"),
                                  encoding="utf-8"))
        case_dir = os.path.join(fixtures_dir, case_id)
        check_report_structure(report, case_id)
        check_no_execution_claims(report, case_id)
        check_fact_vocabulary(report, case_id)
        check_transitions_reference_real_snapshots(case_dir, report, case_id)

        if "profiles" in expected:
            for profile_key, sub in expected["profiles"].items():
                profile = next((p for p in report["profiles"]
                                if p["profile_key"] == profile_key), None)
                if profile is None:
                    fail(f"[{case_id}] profile {profile_key} missing from report")
                entry = next((e for e in profile["extensions"]
                              if e["extension_id"] == sub["extension_id"]), None)
                if entry is None:
                    fail(f"[{case_id}] extension {sub['extension_id']} missing in "
                         f"{profile_key}")
                check_entity(sub, entry, case_id, profile_key)
        else:
            profile = report["profiles"][0]
            entries = {e["extension_id"]: e for e in profile["extensions"]}
            if "entity_ids" in expected:
                if set(entries) != set(expected["entity_ids"]):
                    fail(f"[{case_id}] entity ids {sorted(entries)} != "
                         f"{sorted(expected['entity_ids'])}")
            entry = entries.get(expected["extension_id"])
            if entry is None:
                fail(f"[{case_id}] extension {expected['extension_id']} missing from report")
            check_entity(expected, entry, case_id, profile["profile_key"])
        summary.append(f"[OK] {case_id}")

    # information monotonicity (spec: less evidence never yields stronger claims)
    for strong_case, weak_case in MONOTONICITY_PAIRS:
        def state_of(case_id):
            report = reports[case_id]
            expected = json.load(open(os.path.join(expected_dir, f"{case_id}.json"),
                                      encoding="utf-8"))
            if "profiles" in expected:
                pk = list(expected["profiles"])[0]
                ext_id = expected["profiles"][pk]["extension_id"]
                profile = next(p for p in report["profiles"] if p["profile_key"] == pk)
                return next(e for e in profile["extensions"]
                            if e["extension_id"] == ext_id)["current_state"]
            ext_id = expected["extension_id"]
            profile = report["profiles"][0]
            return next(e for e in profile["extensions"]
                        if e["extension_id"] == ext_id)["current_state"]

        strong_state = state_of(strong_case)
        weak_state = state_of(weak_case)
        if STATE_STRENGTH[weak_state] > STATE_STRENGTH[strong_state]:
            fail(f"information monotonicity violated: {strong_case}={strong_state} but "
                 f"degraded {weak_case}={weak_state}")
        summary.append(f"[OK] monotonicity {strong_case}({strong_state}) >= "
                       f"{weak_case}({weak_state})")

    # irrelevant-evidence invariance
    for base_case, variant_case in IRRELEVANCE_PAIRS:
        def state_of2(case_id):
            report = reports[case_id]
            expected = json.load(open(os.path.join(expected_dir, f"{case_id}.json"),
                                      encoding="utf-8"))
            profile = report["profiles"][0]
            return next(e for e in profile["extensions"]
                        if e["extension_id"] == expected["extension_id"])["current_state"]

        if state_of2(base_case) != state_of2(variant_case):
            fail(f"irrelevant evidence changed the disposition: {base_case}="
                 f"{state_of2(base_case)} vs {variant_case}={state_of2(variant_case)}")
        summary.append(f"[OK] irrelevance {base_case} == {variant_case}")

    for line in summary:
        print(line)
    print(f"\nAll {len(case_ids)} cases plus property checks passed.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <fixtures_dir> <expected_dir> <reports_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
