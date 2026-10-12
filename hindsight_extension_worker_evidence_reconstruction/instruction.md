# Reconstruct Chromium extension Service Worker evidence

Hindsight already parses Chromium extension and Service Worker related browser
artifacts, but analysts still have to correlate those artifacts manually when
reviewing multiple forensic snapshots of the same profile.

Add opt-in support for reconstructing Chromium extension Service Worker state from
a multi-snapshot forensic collection.

The collection format, the four evidence classes, the five disposition states, the
JSON report schema and the CLI contract are documented in:

    /task_docs/extension-worker-state.md

The forensic interpretation rules — what the parsed evidence in each artifact class
entitles the analysis to conclude, and what it does not — are normative in the
reference specimen archive:

    /task_docs/specimens/

Each specimen is a forensic collection together with the ground-truth report that a
correct analysis must produce for it. An implementation is conformant only if it
reproduces every ground-truth report exactly (semantically: entities, states,
revisions, transitions, provenance and uncertainty).

The analysis must:

1. Reuse Hindsight's existing Chromium artifact parsing behavior rather than
   introducing a separate competing browser-profile parser.
2. Determine which browser artifacts realize each documented evidence class from
   Hindsight's existing parsing behavior.
3. Correlate the evidence classes into per-extension runtime entities, keyed by
   profile and extension identity.
4. Reconstruct the five documented states for unseen collections exactly as the
   specimens demonstrate, including when the evidence does not support a strong
   conclusion.
5. Produce evidence provenance and uncertainty that explain why each material
   finding holds and why unsupported conclusions were not drawn. Census records may
   carry integrity metadata; treat it exactly as the specimens demonstrate.
6. Keep existing Hindsight behavior unchanged unless the documented opt-in flag is
   used.

Expose the result through the documented machine-readable JSON report.

Malformed or partially collected browser artifacts must not crash the analysis.
Do not execute extension or Service Worker JavaScript and do not perform network
lookups during forensic analysis.
