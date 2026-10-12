# DBSF Specimen Archive — Verification Manifest

This archive contains specimen firmware images recovered from production devices, together
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
toolchain. Every rule exercised there is demonstrated somewhere in this archive — positively
or negatively. Treat the specimens, and especially the negative examples, as normative.

---
## spec_01.bin

Diagnostic partition unit; single image, standalone.

- Carriers: `64` (39x24, 24bpp)
- Expected recovery: stream `101` — payload (36 bytes):
  sha256 `b4995c933c0857b0d0856e5e49905f7d7fdde5b97975d1324cb40f748d1bb2c3`
  contributing carriers: `[64]`

## spec_02.bin

Boot-splash asset; single image, standalone.

- Carriers: `32` (40x20, 32bpp)
- Expected recovery: stream `102` — payload (34 bytes):
  sha256 `bc47c3a386cd294960827d9765542e6e88594438a68d3c57d681b99a0d2b2bf4`
  contributing carriers: `[32]`

## spec_03.bin

Icon-sheet asset; single image, standalone.

- Carriers: `0` (40x25, 16bpp)
- Expected recovery: stream `103` — payload (27 bytes):
  sha256 `c71f345b091aeebc1b506f13c63f020e08a8bcfa8416224a47ce2c3400479541`
  contributing carriers: `[0]`

## spec_04.bin

Font-atlas asset; single image, standalone.

- Carriers: `0` (44x26, 16bpp)
- Expected recovery: stream `104` — payload (31 bytes):
  sha256 `e0cb9735143e3c52b1db8b7376739977a5a8e34f8a2dc5192c4053021a7480a7`
  contributing carriers: `[0]`

## spec_05.bin

Extended-header asset; single image, standalone.

- Carriers: `16` (42x24, 16bpp)
- Expected recovery: stream `105` — payload (30 bytes):
  sha256 `8b182851d78706f6a0a4be4e03688be01ad1eaecfecbe70fee2151f2fced2faf`
  contributing carriers: `[16]`

## spec_06.bin

Extended-header asset; single image, standalone.

- Carriers: `8` (40x22, 16bpp)
- Expected recovery: stream `106` — payload (30 bytes):
  sha256 `dc0027200134491b5903eaf13bd45a1cc88d62f0f6f9cbf0189840ae95daf8da`
  contributing carriers: `[8]`

## spec_07.bin

Legacy display-profile asset; single image, standalone.

- Carriers: `24` (46x24, 16bpp)
- Expected recovery: stream `107` — payload (34 bytes):
  sha256 `1b13a96abaa4ead396b096c93675a2b9d5d397548d55821bd4aa417e79bfda78`
  contributing carriers: `[24]`

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

## spec_14.bin

Staged firmware bundle from a depth-provisioned device family.

- Carriers: `80` (62291x2, 24bpp)
- Expected recovery: stream `1201` — payload (46674 bytes):
  sha256 `0696f932043eb6458bd4ff808f9ff2bff065e231845e35db0495b57a9e7b9af8`
  contributing carriers: `[80]`
- Expected recovery: stream `1202` — payload (5776 bytes):
  sha256 `632027acd6ab5e043490d55f1048fd9054097d2045ff3018fb2a1755d406548e`
  contributing carriers: `[52]`
- Expected recovery: stream `1203` — payload (664 bytes):
  sha256 `c553c028c83ae86c60613f3e808e666821199c2f93a496a1e82db1b5b931b720`
  contributing carriers: `[50]`
- Nested reporting: 1202 nested inside 1201 with carrier_offsets `[52]` (offsets relative to 1201's payload); 1203 nested inside 1202
  with carrier_offsets `[50]` (relative to 1202's payload). Inside 1203's payload sits a fourth-level carrier (stream `1204` at offset `50`),
  which must NOT be reported because recursive derived-stream scanning stops at maximum depth 3 (depth 1 = `1201`, depth 2 = `1202`,
  depth 3 = `1203`; `1203`'s `nested_derived` must remain empty).

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

## spec_18.bin

Gallery of unusable image assets from the vendor's scrap bin.

- Carriers: `24` (40x25, 24bpp), `3102` (20x10, 8bpp), `4404` (40x25, 32bpp), `8494` (160x160, 24bpp), `85372` (40x25, 24bpp)
- Expected recoveries: **NONE**. A correct implementation produces no derived
  results for this specimen.

