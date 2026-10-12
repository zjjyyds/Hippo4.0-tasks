# Firmware Derived Bitmap Stream Recovery — Field Notes

## Situation

Production firmware images for a family of embedded devices carry secondary diagnostic and
configuration data streams hidden inside the pixel data of their UI bitmap (BMP) resources.
The vendor toolchain that produced these images is lost. No format documentation survives —
neither the packaging of the streams, nor the exact rules by which bitmap pixels carry them.

What we do have is an archive of specimen firmware images, recovered from production devices,
together with a verification manifest recording — for each specimen — every stream a correct
recovery must produce and, just as importantly, what must NOT be produced:

- `/task_docs/samples/` — specimen archive
- `/task_docs/samples/MANIFEST.md` — verification manifest (ground truth)

## Task

Add an opt-in analysis capability to Binwalk that recovers these derived streams:

```rust
binwalker.enable_derived_streams(true)
```

When (and only when) enabled, analysis of a buffer must additionally locate and recover every
derived stream carried by that data and include it in `AnalysisResults.derived`. Recovered
stream payloads must be fed through Binwalk's regular signature analysis engine — with the
caller's include/exclude filters honored — and must themselves be recursively examined for further
derived streams carried by their own contents up to a maximum recursion depth of 3 (the outermost
input scan is depth 1; recursive payload scans proceed through depths 2 and 3, and any stream
reachable only at depth 4 or deeper must never be scanned or reported).

Each derived finding is reported as:

```json
{
  "kind": "bmp-fragmented-stream",
  "stream_id": 17,
  "carrier_offsets": [4096, 16384],
  "total_payload_size": 4096,
  "payload": [80, 75, 3, 4, "... all remaining bytes ..."],
  "file_map": [
    { "offset": 64, "name": "zip", "description": "Zip archive data" }
  ],
  "nested_derived": [ "..." ]
}
```

`nested_derived` (omitted when empty) holds findings recovered from within this stream's own
payload; `file_map` holds signature results with offsets relative to the recovered payload.
`carrier_offsets` is the sorted, deduplicated list of the byte offsets of the carriers that
contributed to this stream — the specimens define precisely what "contributed" means.

Each result, including nested results, must expose a public `payload: Vec<u8>` containing
the complete recovered bytes and serialize it as a JSON array of integers in 0..255.
The abbreviated array above is illustrative; actual output must contain every byte.
`total_payload_size` must equal `payload.len()`. The verifier independently hashes these
bytes and compares the full child signature map with an unmodified, pinned Binwalk scanner
(ignoring per-run signature UUIDs). A digest or a description containing a digest is not
a substitute for the payload. Signature ordering at the same offset is not significant.

## Normative reference

The specimen archive is the ONLY authoritative description of the packaging format and of
all carriage and recovery rules. Behaviors demonstrated there — including every negative
example — are normative. Where the manifest declares that nothing must be recovered, a
correct implementation produces nothing. The acceptance suite grades against unseen firmware
images produced by the same lost toolchain; strictly matching the specimen behaviors is the
only robust strategy.

## Non-negotiable constraints

- Derived scanning is opt-in. With it disabled, Binwalk's existing behavior and serialized
  output must be exactly as before — the `derived` field must not appear at all.
- No new external runtime dependencies or subprocess invocations (`Cargo.toml` and `Cargo.lock` must remain unchanged, and derived stream analysis must execute purely in-process).
- All existing library unit tests and built-in extractor regression tests must keep passing.

## Engineering notes from the field team

- The devices' asset pipelines packed UI sprites aggressively; several specimens carry more
  than one image, and images frequently sit inside larger binary containers. Treat every byte
  of a firmware image as potentially significant.
- Some specimen images look like ordinary bitmaps but are not usable carriers; some look
  corrupted or unusual but are fine. The manifest is the arbiter.
- Recovered payloads in the archive are short strings so they can be verified by eye; on
  real firmware they are arbitrary binary blobs (archives, configs, firmware stages).
