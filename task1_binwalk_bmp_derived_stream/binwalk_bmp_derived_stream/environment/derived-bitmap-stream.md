# Firmware Derived Bitmap Stream — Reduced Field Notes

## Background
Some production firmware BMP resources hide diagnostic/configuration data streams within UI bitmap pixel data. The vendor tools and wire-format documentation have been lost. The specimen archive at `/task_docs/samples/` and `/task_docs/samples/MANIFEST.md` is the normative behavioral reference; unseen acceptance images follow the same protocol.

## Carrier scope
Only **24-bit BI_RGB BMPs with a 40-byte BITMAPINFOHEADER and positive height (bottom-up pixel rows)** are supported. BMPs may occur at arbitrary offsets in a larger firmware input, and multiple carriers may contribute to one logical stream. Correctly account for bottom-up pixel rows and stride/padding. Negative-height top-down BMPs are outside this reduced task. A frame may continue across qualifying BMP carriers at a non-byte-aligned bit phase. Do not sample unrelated or invalid BMP data.

16/32-bit BMPs, indexed palettes, compression, V4/V5 headers and recursive derived scanning are **out of scope** for this reduced task. Negative specimens must produce no derived results.

## API and output
Enable scanning through `binwalker.enable_derived_streams(true)`; leave it disabled by default. Findings appear in `AnalysisResults.derived`, with these observable fields:

- `kind`: `bmp-fragmented-stream`
- `stream_id`: recovered logical stream ID
- `carrier_offsets`: sorted unique offsets of contributing BMP carriers, relative to input bytes
- `total_payload_size`: byte length of the recovered payload
- `payload: Vec<u8>`: every recovered byte, serialized as a JSON array of integers
- `file_map`: Binwalk signature analysis of the actual recovered payload, with offsets relative to that payload

No nested-derived result is required. Reuse the existing signature engine and honor include/exclude filters. The verifier independently hashes the payload (SHA-256) and compares the full child signature map against a trusted pinned Binwalk executable, ignoring UUIDs and result order.

With derived scanning disabled, preserve all preexisting Binwalk behavior and omit the `derived` key entirely.

## Engineering constraints
No additional Cargo dependencies; do not change Cargo.toml or Cargo.lock, spawn subprocesses, or rely on runtime external services. All existing self-contained upstream library, binary and extractor regressions must pass. For extractor integrations requiring optional host-side unpacking tools, preserve their original signature-scanning behavior without requiring those tools to be installed.

## Reverse-engineering boundary
Exact frame headers, bit synchronization, TLV extension behavior, optional XOR, fragment sessions and rejection conditions must be inferred from the sample archive. Hardcoding fixed outputs or specimen IDs is not a valid implementation.
