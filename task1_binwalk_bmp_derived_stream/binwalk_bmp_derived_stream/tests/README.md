# Verifier trust boundary

The test image builds `trusted_signature_reference` against the pristine pinned
Binwalk checkout before installing submission artifacts. The executable, its
runtime libraries, verifier sources and original Cargo file hashes are owned by
root. Submission build scripts and regression tests run as UID 10001.

Only after those steps finish does `verify.py` generate the 57 case families in
a private root-owned temporary directory. Every run changes stream identifiers,
ZIP contents, PNG ancillary content, opaque payload bytes and fixture names.
Every expected stream, including nested streams, must have a complete-payload
SHA-256; missing generator expectations are infrastructure failures.

The submitted harness receives binary input via stdin and the constant logical
path `input.bin`. Its process enters a fresh chroot containing only its executable
and the dependencies copied from the trusted scanner. It drops to UID/GID 65534,
closes inherited file descriptors and sets no-new-privileges. A seccomp filter
blocks networking, process creation and cross-process memory access. No fixtures,
answer manifests, generators, build directories or `/proc` are present there.
Verification fails if this boundary cannot be established; there is no weaker
fallback. Run the verifier as root inside the test container, which needs the
normal Docker `SYS_CHROOT` capability (it does not need privileged mode).

Each derived entry must deliver the full `payload` byte array. The verifier hashes
the bytes itself, validates their length, and compares the entire `file_map` with
the trusted scanner run on the same bytes and include/exclude filters. Signature
UUIDs are ignored and result ordering is normalized. The top-level signature map
is checked too, including with derived mode disabled. Unexpected nested streams
are rejected even when the expected nested list is empty.

This establishes recovered content and observable signature behavior; black-box
tests do not prove which internal algorithm a submission used.

`python3 -B /tests/test_verify.py` runs spoofing/integrity regression tests and a
compiled C probe of the actual filesystem, descriptor, privilege, network and
process boundaries. The Docker image runs these tests during its build.

Manual invocation in the test container:

```sh
python3 -B /tests/verify.py /path/to/submitted/rust_harness \
  /tests/trusted_signature_reference /tests/runtime-root
```
