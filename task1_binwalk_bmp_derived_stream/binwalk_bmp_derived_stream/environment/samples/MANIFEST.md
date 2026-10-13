# DBSF Specimen Archive — Verification Manifest

This reduced archive contains 10 selected 24-bit BMP specimen firmware images recovered from production devices, together
with this manifest: the ground-truth record of what a correct recovery must produce for each
specimen. It is the ONLY authoritative description of the packaging format in existence.

How to read this manifest:

- **Carriers** lists, for each specimen container, the byte offset and geometry of every
  carrier image that participates in the specimen.
- **Expected recoveries** list every logical stream that must be reported, with its stream
  identifier, the size and SHA-256 digest of its recovered payload, and the byte offsets
  of the contributing carriers (as they must appear in the result's `carrier_offsets`).
- Where a specimen declares that **nothing** may be recovered, a correct implementation
  produces no derived results at all — recovering anything there is a defect.

The acceptance suite grades against unseen firmware images produced by the same (lost) vendor
toolchain. The public specimens demonstrate the basic behaviors; the compact boundary
semantics in `/task_docs/derived-bitmap-stream.md` are also authoritative.
Unseen inputs may combine these rules. Treat negative specimens as normative.

---

## spec_01.bin

Diagnostic partition unit; single image, standalone.

- Carriers: `64` (39x24, 24bpp)
- Expected recovery: stream `101` — payload (36 bytes):
  sha256 `b4995c933c0857b0d0856e5e49905f7d7fdde5b97975d1324cb40f748d1bb2c3`
  contributing carriers: `[64]`

## spec_08.bin

Multi-asset resource unit; single image.

- Carriers: `100` (251x2, 24bpp)
- Expected recovery: stream `108` — payload (34 bytes):
  sha256 `27250c813adc571c2daeef7b964bf3c7db8ea49f4106b4f20bab6d915d3c9742`
  contributing carriers: `[100]`
- Expected recovery: stream `109` — payload (22 bytes):
  sha256 `9bc3ba3f7af3527121be11fd501bf1af09791b516f0e267d2b5d75dd13ed684a`
  contributing carriers: `[100]`

## spec_09.bin

Two images in one container.

- Carriers: `128` (130x1, 24bpp), `614` (39x2, 24bpp)
- Expected recovery: stream `110` — payload (34 bytes):
  sha256 `d6aaeb1354a8089244db8b617d037271e5ed1b42a7ffd9e0edb81b71b53e91ed`
  contributing carriers: `[128, 614]`

## spec_10.bin

Two images in one container.

- Carriers: `60` (9x1, 24bpp), `172` (101x2, 24bpp)
- Expected recovery: stream `111` — payload (34 bytes):
  sha256 `63a66dc3e68af665ea4cc23e829b41dce297925a8fce358148e04f189e8c09c3`
  contributing carriers: `[60, 172]`

## spec_11.bin

Field-conditioned asset; single image, standalone.

- Carriers: `0` (50x30, 24bpp)
- Expected recovery: stream `112` — payload (35 bytes):
  sha256 `1f12fe6d7f24eb932f04e77097c8a6449f95199b58bdc80e37eae020165d7ffa`
  contributing carriers: `[0]`

## spec_12.bin

Single image, standalone.

- Carriers: `64` (227x2, 24bpp)
- Expected recovery: stream `113` — payload (126 bytes):
  sha256 `684dc6dfaeaaf2a7b1f6a13dabb7eea435f219f4061361287a4ab7de44d967f6`
  contributing carriers: `[64]`

## spec_13.bin

Two images in one container.

- Carriers: `90` (44x26, 24bpp), `3626` (44x26, 24bpp)
- Expected recovery: stream `114` — payload (30 bytes):
  sha256 `487f7d9d3dbdfb4f6a05405ce69a9caaf3eb1d702e61749251c713beed7e6861`
  contributing carriers: `[90, 3626]`

## spec_15.bin

Legacy-tool artifact; single image, standalone.

- Carriers: `40` (70x40, 24bpp)
- Expected recovery: stream `115` — payload (31 bytes):
  sha256 `f8a551885c644f9d9ca4f4b20df958757a0e27494cc5301c26d8fbb85be9e9b5`
  contributing carriers: `[40]`

## spec_16.bin

Two images in one container.

- Carriers: `56` (40x1, 24bpp), `294` (99x2, 24bpp)
- Expected recovery: stream `116` — payload (29 bytes):
  sha256 `ed44a5ac058e7cbbb3d98d1e8ac3d0f189794b8cc4dd084fb75a9654589f07a4`
  contributing carriers: `[294]`

## spec_17.bin

Gallery of defective units rejected by the vendor's QA bench.

- Carriers: `24` (73x2, 24bpp), `542` (73x2, 24bpp), `1060` (73x2, 24bpp), `1578` (73x2, 24bpp), `2096` (59x2, 24bpp), `2534` (163x2, 24bpp), `3596` (167x2, 24bpp), `4682` (73x2, 24bpp), `5200` (73x2, 24bpp), `5718` (71x2, 24bpp), `6228` (79x2, 24bpp), `6786` (40x1, 24bpp), `6984` (101x2, 24bpp), `7670` (301x2, 24bpp), `9556` (75x2, 24bpp)
- Expected recoveries: **NONE**. A correct implementation produces no derived
  results for this specimen.
