#!/usr/bin/env python3
"""
Test Case Generator for Binwalk Fragmented & Recursive BMP Derived Stream (DBSF v2.2)
Includes bit-level synchronization, 16-bit RGB555 carriers, and TLV Rolling XOR extensions.
"""

import os
import sys
import json
import struct
import random
import binascii
import hashlib
import zipfile
import io
import secrets
from pathlib import Path

# Wire magic: deliberately non-textual binary constant (rev D layout)
DBSF_MAGIC = bytes([0xB6, 0x5A, 0xE3, 0x81, 0x0C, 0xF4, 0x29, 0xD8])

_PAYLOAD_BLOBS = []
_STREAM_FRAGS = {}
_RANDOMIZE = False
_STREAM_ID_MASK = 0

def build_zip_payload(content_str="DBSF_SECRET_EMBEDDED_ZIP_PAYLOAD"):
    if _RANDOMIZE:
        content_str = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in content_str)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("secret.txt", content_str)
    zip_bytes = buf.getvalue()
    digest = hashlib.sha256(zip_bytes).hexdigest()
    trailer = f"Copyright sha256:{digest}\x00".encode("ascii")
    full = zip_bytes + trailer + (os.urandom(16) if _RANDOMIZE else b'')
    _PAYLOAD_BLOBS.append(("zip", full, len(zip_bytes), digest))
    return full

def build_png_payload():
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    if _RANDOMIZE:
        text_data = b'nonce\x00' + os.urandom(16).hex().encode('ascii')
        chunk = b'tEXt' + text_data
        png_bytes = png_bytes[:-12] + struct.pack('>I', len(text_data)) + chunk + struct.pack('>I', binascii.crc32(chunk) & 0xFFFFFFFF) + png_bytes[-12:]
    digest = hashlib.sha256(png_bytes).hexdigest()
    trailer = f"Copyright sha256:{digest}\x00".encode("ascii")
    full = png_bytes + trailer
    _PAYLOAD_BLOBS.append(("png", full, len(png_bytes), digest))
    return full
def build_tlv(tag, value_bytes):
    return bytes([tag, len(value_bytes)]) + value_bytes

def build_dbsf_v2_frame(
    fragment_data,
    stream_id=1,
    fragment_index=0,
    fragment_count=1,
    payload_offset=0,
    total_len=None,
    total_crc=None,
    header_ext=b"",
    version=2,
    flags=0,
    reserved=0,
    corrupt_frag_crc=False,
    corrupt_total_crc=False,
    declared_header_len=None,
    declared_frag_len=None,
    xor_key=None
):
    # Rev D core layout (44 bytes total): magic(8) | StreamId u32 | FragmentCount u16 |
    # FragmentIndex u16 | FragmentLength u32 | PayloadOffset u32 | TotalLength u32 |
    # TotalCRC u32 | FragmentCRC u32 | Version u8 | Flags u8 | Reserved u16 |
    # HeaderLength u32 (tail)
    global DBSF_MAGIC
    stream_id ^= _STREAM_ID_MASK

    # If XOR key provided, scramble the fragment data to embed and attach key TLV (tag 0x01)
    actual_data_to_embed = fragment_data
    if xor_key:
        actual_data_to_embed = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(fragment_data))
        header_ext = header_ext + build_tlv(0x01, xor_key)

    CORE_HEADER_SIZE = 44
    hlen = (CORE_HEADER_SIZE + len(header_ext)) if declared_header_len is None else declared_header_len
    flen = len(fragment_data) if declared_frag_len is None else declared_frag_len
    tlen = flen if total_len is None else total_len

    fcrc = binascii.crc32(fragment_data) & 0xFFFFFFFF
    if corrupt_frag_crc:
        fcrc ^= 0xDEADBEEF

    tcrc = (binascii.crc32(fragment_data) & 0xFFFFFFFF) if total_crc is None else total_crc
    if corrupt_total_crc:
        tcrc ^= 0xCAFEBABE

    header = DBSF_MAGIC + struct.pack(
        "<IHHIIIIIBBHI",
        stream_id, fragment_count, fragment_index,
        flen, payload_offset,
        tlen, tcrc, fcrc,
        version, flags, reserved, hlen
    ) + header_ext
    if not corrupt_frag_crc and not corrupt_total_crc and declared_frag_len is None and declared_header_len is None and reserved == 0:
        _STREAM_FRAGS.setdefault((stream_id, fragment_count, tlen, tcrc), {})[fragment_index] = (payload_offset, fragment_data)

    return header + actual_data_to_embed
def frame_to_bits(frame_bytes):
    bits = []
    for b in frame_bytes:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)
    return bits

def _tz(m):
    """trailing zeros of a nonzero mask"""
    return (m & -m).bit_length() - 1

def build_bmp(width, height, bpp=24, bits_to_embed=None, pad_noise=True, random_alpha=True, slip_bits=0, compression=0, dib_size=40, embed_start_bit=None, bisize_image=None, masks=None):
    w = width
    h = abs(height)
    top_down = (height < 0)
    bytes_per_pixel = bpp // 8
    row_stride = ((w * bpp + 31) // 32) * 4
    row_pixel_bytes = w * bytes_per_pixel
    padding_len = row_stride - row_pixel_bytes

    # Effective 16-bit color masks (R, G, B): explicit param, else BITFIELDS default 565 / RGB default 555
    if masks is None:
        eff = (0xF800, 0x07E0, 0x001F) if compression == 3 else (0x7C00, 0x03E0, 0x001F)
    else:
        eff = tuple(masks)

    pixel_array = bytearray(h * row_stride)

    # Leading random bits before the embedded frame: bit-phase slip placement.
    # embed_start_bit supersedes slip_bits when provided (generalized placement).
    bits_seq = []
    prefix_bits = slip_bits if embed_start_bit is None else embed_start_bit
    if prefix_bits > 0:
        bits_seq.extend([random.randint(0, 1) for _ in range(prefix_bits)])
    if bits_to_embed:
        bits_seq.extend(bits_to_embed)

    bit_idx = 0
    total_bits = len(bits_seq)

    for y in range(h):
        r = y if top_down else (h - 1 - y)
        row_offset = r * row_stride
        for x in range(w):
            px_offset = row_offset + x * bytes_per_pixel
            
            b_bit = bits_seq[bit_idx] if bit_idx < total_bits else random.randint(0, 1)
            if bit_idx < total_bits: bit_idx += 1
            g_bit = bits_seq[bit_idx] if bit_idx < total_bits else random.randint(0, 1)
            if bit_idx < total_bits: bit_idx += 1
            r_bit = bits_seq[bit_idx] if bit_idx < total_bits else random.randint(0, 1)
            if bit_idx < total_bits: bit_idx += 1

            if bpp == 16:
                if compression == 3:
                    # BI_BITFIELDS with (possibly non-contiguous) masks: sample position
                    # is the lowest set bit of each channel mask
                    mR, mG, mB = eff
                    spare = 0xFFFF & ~(mR | mG | mB)
                    px16 = (random.randint(0, 0xFFFF) & spare) \
                        | (b_bit << _tz(mB)) | (g_bit << _tz(mG)) | (r_bit << _tz(mR))
                else:
                    # BI_RGB RGB555: 16-bit word, B=0..4, G=5..9, R=10..14, bit 15=0
                    b_val = (random.randint(0, 31) & ~1) | b_bit
                    g_val = (random.randint(0, 31) & ~1) | g_bit
                    r_val = (random.randint(0, 31) & ~1) | r_bit
                    px16 = b_val | (g_val << 5) | (r_val << 10)
                pixel_array[px_offset : px_offset + 2] = struct.pack("<H", px16)
            elif bpp == 24:
                b_val = (random.randint(0, 255) & ~1) | b_bit
                g_val = (random.randint(0, 255) & ~1) | g_bit
                r_val = (random.randint(0, 255) & ~1) | r_bit
                pixel_array[px_offset] = b_val
                pixel_array[px_offset + 1] = g_val
                pixel_array[px_offset + 2] = r_val
            elif bpp == 32:
                b_val = (random.randint(0, 255) & ~1) | b_bit
                g_val = (random.randint(0, 255) & ~1) | g_bit
                r_val = (random.randint(0, 255) & ~1) | r_bit
                a_val = random.randint(0, 255) if random_alpha else 255
                pixel_array[px_offset] = b_val
                pixel_array[px_offset + 1] = g_val
                pixel_array[px_offset + 2] = r_val
                pixel_array[px_offset + 3] = a_val

        for p in range(padding_len):
            pixel_array[row_offset + row_pixel_bytes + p] = random.randint(0, 255) if pad_noise else 0

    masks_bytes = b""
    bi_size_image = len(pixel_array) if bisize_image is None else bisize_image
    if dib_size == 40:
        if compression == 3:
            masks_bytes = struct.pack("<III", eff[0], eff[1], eff[2])
        bf_off_bits = 54 + len(masks_bytes)
        dib_header = struct.pack(
            "<IiiHHIIiiII",
            40, w, height, 1, bpp,
            compression, bi_size_image, 2835, 2835, 0, 0
        )
    elif dib_size in (108, 124):
        # BITMAPV4HEADER (108) / BITMAPV5HEADER (124): color masks are embedded
        # DIB member fields immediately after the core 40 bytes (offsets 40..52)
        if compression == 3:
            red_mask, green_mask, blue_mask = eff
        else:
            red_mask, green_mask, blue_mask = 0x7C00, 0x03E0, 0x001F
        alpha_mask = 0
        cs_type = 0x73524742  # 'sRGB'
        endpoints = b"\x00" * 36
        gamma_r = gamma_g = gamma_b = 0
        base40 = struct.pack(
            "<IiiHHIIiiII",
            dib_size, w, height, 1, bpp,
            compression, bi_size_image, 2835, 2835, 0, 0
        )
        masks_v = struct.pack("<IIII", red_mask, green_mask, blue_mask, alpha_mask)
        extra_v4 = struct.pack("<I", cs_type) + endpoints + struct.pack("<III", gamma_r, gamma_g, gamma_b)
        dib_header = base40 + masks_v + extra_v4
        if dib_size == 124:
            # V5 tail: intent + profileData + profileSize + reserved
            dib_header += struct.pack("<IIII", 4, 0, 0, 0)
        masks_bytes = b""
        bf_off_bits = 14 + dib_size
    else:
        raise ValueError(f"Unsupported dib_size: {dib_size}")

    bf_type = b"BM"
    bf_size = bf_off_bits + len(pixel_array)
    file_header = bf_type + struct.pack("<IHHI", bf_size, 0, 0, bf_off_bits)

    return file_header + dib_header + masks_bytes + bytes(pixel_array)

def split_payload_with_offsets(payload, num_fragments):
    chunk_size = (len(payload) + num_fragments - 1) // num_fragments
    slices = []
    for i in range(num_fragments):
        start = i * chunk_size
        end = min(start + chunk_size, len(payload))
        slices.append((start, payload[start:end]))
    return slices

def dims_for_bits(nbits, min_height=2):
    """Smallest carrier geometry whose sampled capacity (w*h*3 bits) covers nbits.
    Odd width keeps capacity % 8 in {2, 6} so default split points land mid-byte."""
    h = min_height
    w = (nbits + 3 * h - 1) // (3 * h)
    if w % 2 == 0:
        w += 1
    return w, h

def build_palette_bmp(width, height, raw_decoy=b""):
    """8-bit paletted BMP: an UNSUPPORTED carrier per the spec. Optionally plants raw
    decoy bytes (e.g. a fake BWDERIV2 header) into the raw pixel-array bytes so that
    implementations which sample raw file bytes instead of qualified carriers misfire."""
    stride = ((width * 8 + 31) // 32) * 4
    pixel_array = bytearray(height * stride)
    if raw_decoy:
        assert len(raw_decoy) <= len(pixel_array)
        pixel_array[0:len(raw_decoy)] = raw_decoy
    palette = b"".join(struct.pack("<BBBB", i & 0xFF, (i * 3) & 0xFF, (i * 7) & 0xFF, 0) for i in range(256))
    bf_off_bits = 14 + 40 + len(palette)
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40, width, height, 1, 8,
        0, len(pixel_array), 2835, 2835, 0, 0
    )
    file_header = b"BM" + struct.pack("<IHHI", bf_off_bits + len(pixel_array), 0, 0, bf_off_bits)
    return file_header + dib_header + palette + bytes(pixel_array)

def generate_all_cases(output_dir):
    global _RANDOMIZE, _STREAM_ID_MASK
    _PAYLOAD_BLOBS.clear()
    _STREAM_FRAGS.clear()
    _RANDOMIZE = True
    random.seed(secrets.randbits(128))
    _STREAM_ID_MASK = secrets.randbits(32)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    manifest = []

    # CASE 1: Single-fragment 24-bit BMP basic valid DBSF v2 + ZIP payload
    zip_payload = build_zip_payload("CASE1_SINGLE_FRAG_24BIT")
    frame1 = build_dbsf_v2_frame(zip_payload, stream_id=1, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp1 = build_bmp(width=80, height=50, bpp=24, bits_to_embed=frame_to_bits(frame1))
    p1 = out_path / "case01_single_frag_24bit.bin"
    p1.write_bytes(bmp1)
    manifest.append({
        "id": "case01_single_frag_24bit",
        "file": p1.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 1,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Single-fragment DBSF v2 in 24-bit bottom-up BMP"
    })

    # CASE 2: Single-fragment 32-bit BMP with random Alpha LSBs
    zip_payload = build_zip_payload("CASE2_32BIT_RANDOM_ALPHA")
    frame2 = build_dbsf_v2_frame(zip_payload, stream_id=2, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp2 = build_bmp(width=80, height=50, bpp=32, bits_to_embed=frame_to_bits(frame2), random_alpha=True)
    p2 = out_path / "case02_single_frag_32bit_alpha.bin"
    p2.write_bytes(bmp2)
    manifest.append({
        "id": "case02_single_frag_32bit_alpha",
        "file": p2.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 2,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Single-fragment DBSF v2 in 32-bit BMP with randomized Alpha channel"
    })

    # CASE 3: Single-fragment 16-bit BMP carrier (RGB555 format)
    zip_payload = build_zip_payload("CASE3_16BIT_RGB555_CARRIER")
    frame3 = build_dbsf_v2_frame(zip_payload, stream_id=3, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp3 = build_bmp(width=80, height=50, bpp=16, bits_to_embed=frame_to_bits(frame3))
    p3 = out_path / "case03_single_frag_16bit_rgb555.bin"
    p3.write_bytes(bmp3)
    manifest.append({
        "id": "case03_single_frag_16bit_rgb555",
        "file": p3.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 3,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Embedded 16-bit BMP carrier (RGB555) with 5-bit color bitmask shifts"
    })

    # CASE 4: Single-fragment 24-bit BMP with width=101 row padding
    zip_payload = build_zip_payload("CASE4_PADDING_STRIDE")
    frame4 = build_dbsf_v2_frame(zip_payload, stream_id=4, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp4 = build_bmp(width=101, height=40, bpp=24, bits_to_embed=frame_to_bits(frame4), pad_noise=True)
    p4 = out_path / "case04_single_frag_padding.bin"
    p4.write_bytes(bmp4)
    manifest.append({
        "id": "case04_single_frag_padding",
        "file": p4.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 4,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Single-fragment DBSF v2 with width=101 requiring scanline padding skip"
    })

    # CASE 5: Single-fragment bottom-up vs top-down (bottom-up)
    zip_payload = build_zip_payload("CASE5_BOTTOM_UP")
    frame5 = build_dbsf_v2_frame(zip_payload, stream_id=5, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp5 = build_bmp(width=75, height=50, bpp=24, bits_to_embed=frame_to_bits(frame5))
    p5 = out_path / "case05_single_frag_bottom_up.bin"
    p5.write_bytes(bmp5)
    manifest.append({
        "id": "case05_single_frag_bottom_up",
        "file": p5.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 5,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Bottom-up BMP (height > 0) with single DBSF v2 stream"
    })

    # CASE 6: Single-fragment top-down (height < 0)
    zip_payload = build_zip_payload("CASE6_TOP_DOWN")
    frame6 = build_dbsf_v2_frame(zip_payload, stream_id=6, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp6 = build_bmp(width=75, height=-50, bpp=24, bits_to_embed=frame_to_bits(frame6))
    p6 = out_path / "case06_single_frag_top_down.bin"
    p6.write_bytes(bmp6)
    manifest.append({
        "id": "case06_single_frag_top_down",
        "file": p6.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 6,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Top-down BMP (height < 0) with single DBSF v2 stream"
    })

    # CASE 7: Bit-level synchronization (5 unaligned slip bits before 64-bit preamble)
    zip_payload = build_zip_payload("CASE7_BIT_PHASE_SLIP_SYNC")
    frame7 = build_dbsf_v2_frame(zip_payload, stream_id=7, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp7 = build_bmp(width=85, height=55, bpp=24, bits_to_embed=frame_to_bits(frame7), slip_bits=5)
    p7 = out_path / "case07_bit_slip_synchronization.bin"
    p7.write_bytes(bmp7)
    manifest.append({
        "id": "case07_bit_slip_synchronization",
        "file": p7.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 7,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Bitstream has 5 unaligned slip bits before BWDERIV2 preamble; requires bit-level sync window"
    })

    # CASE 8: TLV Header Extension Tag 0x01 Rolling XOR descrambling
    zip_payload = build_zip_payload("CASE8_TLV_ROLLING_XOR")
    xor_key8 = b"\x3c\xa5\x5a\xc3"
    frame8 = build_dbsf_v2_frame(zip_payload, stream_id=8, fragment_index=0, fragment_count=1, payload_offset=0, xor_key=xor_key8)
    bmp8 = build_bmp(width=85, height=55, bpp=24, bits_to_embed=frame_to_bits(frame8))
    p8 = out_path / "case08_tlv_rolling_xor_descramble.bin"
    p8.write_bytes(bmp8)
    manifest.append({
        "id": "case08_tlv_rolling_xor_descramble",
        "file": p8.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 8,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "TLV Tag 0x01 rolling XOR key; fragment payload scrambled in carrier and descrambled before CRC"
    })

    # CASE 9: TLV Header Extension with unrecognized critical tag (0x85) -> REJECT
    zip_payload = build_zip_payload("CASE9_CRITICAL_TAG")
    bad_tlv = build_tlv(0x85, b"UNSUPPORTED_CRITICAL_PAYLOAD")
    frame9 = build_dbsf_v2_frame(zip_payload, stream_id=9, header_ext=bad_tlv)
    bmp9 = build_bmp(width=85, height=55, bpp=24, bits_to_embed=frame_to_bits(frame9))
    p9 = out_path / "case09_tlv_critical_tag_reject.bin"
    p9.write_bytes(bmp9)
    manifest.append({
        "id": "case09_tlv_critical_tag_reject",
        "file": p9.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "TLV extension contains unrecognized critical tag 0x85; candidate must be rejected"
    })

    # CASE 10: Multi-fragment in-order (Stream 10 split across 3 BMPs sequentially)
    zip_payload = build_zip_payload("CASE10_MULTI_FRAG_IN_ORDER")
    slices10 = split_payload_with_offsets(zip_payload, 3)
    total_crc10 = binascii.crc32(zip_payload) & 0xFFFFFFFF
    total_len10 = len(zip_payload)

    bmps10 = []
    for idx, (p_off, chunk) in enumerate(slices10):
        f = build_dbsf_v2_frame(
            chunk, stream_id=10, fragment_index=idx, fragment_count=3,
            payload_offset=p_off, total_len=total_len10, total_crc=total_crc10
        )
        b = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f))
        bmps10.append(b)

    outer10 = os.urandom(1024) + bmps10[0] + os.urandom(2048) + bmps10[1] + os.urandom(1024) + bmps10[2] + os.urandom(512)
    off0 = 1024
    off1 = off0 + len(bmps10[0]) + 2048
    off2 = off1 + len(bmps10[1]) + 1024
    p10 = out_path / "case10_multi_frag_in_order.bin"
    p10.write_bytes(outer10)
    manifest.append({
        "id": "case10_multi_frag_in_order",
        "file": p10.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 10,
            "carrier_offsets": [off0, off1, off2],
            "total_payload_size": total_len10,
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Stream 10 fragmented into 3 parts across 3 separate BMP carriers in sequential order"
    })

    # CASE 11: Multi-fragment out-of-order in file (Frag 2 at off0, Frag 0 at off1, Frag 1 at off2)
    zip_payload = build_zip_payload("CASE11_MULTI_FRAG_OUT_OF_ORDER")
    slices11 = split_payload_with_offsets(zip_payload, 3)
    total_crc11 = binascii.crc32(zip_payload) & 0xFFFFFFFF
    total_len11 = len(zip_payload)

    f11_frag0 = build_dbsf_v2_frame(slices11[0][1], stream_id=15, fragment_index=0, fragment_count=3, payload_offset=slices11[0][0], total_len=total_len11, total_crc=total_crc11)
    f11_frag1 = build_dbsf_v2_frame(slices11[1][1], stream_id=15, fragment_index=1, fragment_count=3, payload_offset=slices11[1][0], total_len=total_len11, total_crc=total_crc11)
    f11_frag2 = build_dbsf_v2_frame(slices11[2][1], stream_id=15, fragment_index=2, fragment_count=3, payload_offset=slices11[2][0], total_len=total_len11, total_crc=total_crc11)

    bmp11_frag0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f11_frag0))
    bmp11_frag1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f11_frag1))
    bmp11_frag2 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f11_frag2))

    outer11 = os.urandom(2048) + bmp11_frag2 + os.urandom(4096) + bmp11_frag0 + os.urandom(1024) + bmp11_frag1 + os.urandom(512)
    c_off_frag2 = 2048
    c_off_frag0 = c_off_frag2 + len(bmp11_frag2) + 4096
    c_off_frag1 = c_off_frag0 + len(bmp11_frag0) + 1024
    sorted_offsets_11 = sorted([c_off_frag0, c_off_frag1, c_off_frag2])

    p11 = out_path / "case11_multi_frag_out_of_order.bin"
    p11.write_bytes(outer11)
    manifest.append({
        "id": "case11_multi_frag_out_of_order",
        "file": p11.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 15,
            "carrier_offsets": sorted_offsets_11,
            "total_payload_size": total_len11,
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Stream 15 fragments stored physically out of sequence (frag 2, 0, 1); reassembly must place by payload_offset"
    })

    # CASE 12: Multi-fragment with missing fragment
    slices12 = split_payload_with_offsets(zip_payload, 3)
    f12_0 = build_dbsf_v2_frame(slices12[0][1], stream_id=18, fragment_index=0, fragment_count=3, payload_offset=slices12[0][0], total_len=total_len11, total_crc=total_crc11)
    f12_2 = build_dbsf_v2_frame(slices12[2][1], stream_id=18, fragment_index=2, fragment_count=3, payload_offset=slices12[2][0], total_len=total_len11, total_crc=total_crc11)
    bmp12_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f12_0))
    bmp12_2 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f12_2))
    outer12 = os.urandom(1024) + bmp12_0 + os.urandom(2048) + bmp12_2
    p12 = out_path / "case12_multi_frag_missing.bin"
    p12.write_bytes(outer12)
    manifest.append({
        "id": "case12_multi_frag_missing",
        "file": p12.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Stream 18 is missing fragment 1; must safely reject without producing stream"
    })

    # CASE 13: Corrupted fragment CRC
    slices13 = split_payload_with_offsets(zip_payload, 2)
    f13_0 = build_dbsf_v2_frame(slices13[0][1], stream_id=19, fragment_index=0, fragment_count=2, payload_offset=slices13[0][0], total_len=total_len11, total_crc=total_crc11, corrupt_frag_crc=True)
    f13_1 = build_dbsf_v2_frame(slices13[1][1], stream_id=19, fragment_index=1, fragment_count=2, payload_offset=slices13[1][0], total_len=total_len11, total_crc=total_crc11)
    bmp13_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f13_0))
    bmp13_1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f13_1))
    outer13 = os.urandom(1024) + bmp13_0 + os.urandom(1024) + bmp13_1
    p13 = out_path / "case13_corrupted_frag_crc.bin"
    p13.write_bytes(outer13)
    manifest.append({
        "id": "case13_corrupted_frag_crc",
        "file": p13.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Fragment 0 has corrupted FragmentCRC; stream must be rejected"
    })

    # CASE 14: Corrupted total CRC
    slices14 = split_payload_with_offsets(zip_payload, 2)
    f14_0 = build_dbsf_v2_frame(slices14[0][1], stream_id=20, fragment_index=0, fragment_count=2, payload_offset=slices14[0][0], total_len=total_len11, total_crc=total_crc11, corrupt_total_crc=True)
    f14_1 = build_dbsf_v2_frame(slices14[1][1], stream_id=20, fragment_index=1, fragment_count=2, payload_offset=slices14[1][0], total_len=total_len11, total_crc=total_crc11, corrupt_total_crc=True)
    bmp14_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f14_0))
    bmp14_1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f14_1))
    outer14 = os.urandom(1024) + bmp14_0 + os.urandom(1024) + bmp14_1
    p14 = out_path / "case14_corrupted_total_crc.bin"
    p14.write_bytes(outer14)
    manifest.append({
        "id": "case14_corrupted_total_crc",
        "file": p14.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Total CRC corrupted across all fragments; stream reassembly must fail CRC validation"
    })

    # CASE 15: Duplicate fragment index
    f15_0a = build_dbsf_v2_frame(slices14[0][1], stream_id=22, fragment_index=0, fragment_count=2, payload_offset=slices14[0][0], total_len=total_len11, total_crc=total_crc11)
    f15_0b = build_dbsf_v2_frame(b"DUPLICATE_DIFFERENT_CHUNK", stream_id=22, fragment_index=0, fragment_count=2, payload_offset=slices14[0][0], total_len=total_len11, total_crc=total_crc11)
    bmp15_0a = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f15_0a))
    bmp15_0b = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f15_0b))
    outer15 = os.urandom(1024) + bmp15_0a + os.urandom(1024) + bmp15_0b
    p15 = out_path / "case15_duplicate_frag_index.bin"
    p15.write_bytes(outer15)
    manifest.append({
        "id": "case15_duplicate_frag_index",
        "file": p15.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Two conflicting fragments claiming sequence index 0; must reject stream"
    })

    # CASE 16: Fragment range overlap rejection:
    # Frag 0 covers [0, 80), Frag 1 declares offset 60 (covers [60, 140)) -> 20 bytes overlap!
    full_zip = build_zip_payload("CASE16_OVERLAP_PAYLOAD")
    f16_0 = build_dbsf_v2_frame(full_zip[0:80], stream_id=23, fragment_index=0, fragment_count=2, payload_offset=0, total_len=len(full_zip), total_crc=binascii.crc32(full_zip) & 0xFFFFFFFF)
    f16_1 = build_dbsf_v2_frame(full_zip[60:], stream_id=23, fragment_index=1, fragment_count=2, payload_offset=60, total_len=len(full_zip), total_crc=binascii.crc32(full_zip) & 0xFFFFFFFF)
    bmp16_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f16_0))
    bmp16_1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f16_1))
    outer16 = os.urandom(512) + bmp16_0 + os.urandom(512) + bmp16_1
    p16 = out_path / "case16_fragment_range_overlap.bin"
    p16.write_bytes(outer16)
    manifest.append({
        "id": "case16_fragment_range_overlap",
        "file": p16.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Fragments have overlapping payload byte ranges [0, 80) and [60, 140); must be rejected"
    })

    # CASE 17: Fragment range gap rejection:
    # Frag 0 covers [0, 50), Frag 1 declares offset 70 (covers [70, 140)) -> gap of 20 bytes!
    f17_0 = build_dbsf_v2_frame(full_zip[0:50], stream_id=24, fragment_index=0, fragment_count=2, payload_offset=0, total_len=len(full_zip), total_crc=binascii.crc32(full_zip) & 0xFFFFFFFF)
    f17_1 = build_dbsf_v2_frame(full_zip[70:], stream_id=24, fragment_index=1, fragment_count=2, payload_offset=70, total_len=len(full_zip), total_crc=binascii.crc32(full_zip) & 0xFFFFFFFF)
    bmp17_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f17_0))
    bmp17_1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f17_1))
    outer17 = os.urandom(512) + bmp17_0 + os.urandom(512) + bmp17_1
    p17 = out_path / "case17_fragment_range_gap.bin"
    p17.write_bytes(outer17)
    manifest.append({
        "id": "case17_fragment_range_gap",
        "file": p17.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Fragments leave an uncovered gap in payload range [50, 70); must be rejected"
    })

    # CASE 18: Single large BMP carrier carrying MULTIPLE fragments of the SAME stream
    slices18 = split_payload_with_offsets(full_zip, 2)
    f18_0 = build_dbsf_v2_frame(slices18[0][1], stream_id=25, fragment_index=0, fragment_count=2, payload_offset=slices18[0][0], total_len=len(full_zip), total_crc=binascii.crc32(full_zip) & 0xFFFFFFFF)
    f18_1 = build_dbsf_v2_frame(slices18[1][1], stream_id=25, fragment_index=1, fragment_count=2, payload_offset=slices18[1][0], total_len=len(full_zip), total_crc=binascii.crc32(full_zip) & 0xFFFFFFFF)
    pad18 = os.urandom(200 - len(f18_0)) if len(f18_0) < 200 else b""
    stream18 = f18_0 + pad18 + f18_1
    bmp18 = build_bmp(width=100, height=60, bpp=24, bits_to_embed=frame_to_bits(stream18))
    outer18 = os.urandom(12288) + bmp18 + os.urandom(1024)
    p18 = out_path / "case18_single_carrier_multi_frags.bin"
    p18.write_bytes(outer18)
    manifest.append({
        "id": "case18_single_carrier_multi_frags",
        "file": p18.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 25,
            "carrier_offsets": [12288],
            "total_payload_size": len(full_zip),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Single large carrier at 12288 carries both Frag 0 and Frag 1 of Stream 25; carrier_offsets deduplicated"
    })

    # CASE 19: Dual concurrent streams in single file (Stream 31 with 2 frags, Stream 42 with 1 frag)
    zip_part = build_zip_payload("CASE19_STREAM31_ZIP")
    png_part = build_png_payload()
    slices19 = split_payload_with_offsets(zip_part, 2)
    crc19_31 = binascii.crc32(zip_part) & 0xFFFFFFFF
    len19_31 = len(zip_part)

    f19_31_0 = build_dbsf_v2_frame(slices19[0][1], stream_id=31, fragment_index=0, fragment_count=2, payload_offset=slices19[0][0], total_len=len19_31, total_crc=crc19_31)
    f19_31_1 = build_dbsf_v2_frame(slices19[1][1], stream_id=31, fragment_index=1, fragment_count=2, payload_offset=slices19[1][0], total_len=len19_31, total_crc=crc19_31)
    f19_42 = build_dbsf_v2_frame(png_part, stream_id=42, fragment_index=0, fragment_count=1, payload_offset=0)

    bmp19_31_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f19_31_0))
    bmp19_31_1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f19_31_1))
    bmp19_42 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f19_42))

    outer19 = (os.urandom(1024) + bmp19_31_0 +
               os.urandom(2048) + bmp19_42 +
               os.urandom(1024) + bmp19_31_1)
    off19_31_0 = 1024
    off19_42 = off19_31_0 + len(bmp19_31_0) + 2048
    off19_31_1 = off19_42 + len(bmp19_42) + 1024

    p19 = out_path / "case19_dual_streams.bin"
    p19.write_bytes(outer19)
    manifest.append({
        "id": "case19_dual_streams",
        "file": p19.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [
            {
                "kind": "bmp-fragmented-stream",
                "stream_id": 31,
                "carrier_offsets": [off19_31_0, off19_31_1],
                "total_payload_size": len19_31,
                "expected_child_signatures": [{"name": "zip", "offset": 0}]
            },
            {
                "kind": "bmp-fragmented-stream",
                "stream_id": 42,
                "carrier_offsets": [off19_42],
                "total_payload_size": len(png_part),
                "expected_child_signatures": [{"name": "png", "offset": 0}]
            }
        ],
        "description": "Two independent streams interleaved in same binary: Stream 31 (2 fragments) and Stream 42 (1 fragment)"
    })

    # CASE 20: Recursive nested stream:
    # Outer Stream 100 payload contains ZIP at offset 0, and a nested BMP at offset 256.
    # The nested BMP contains Stream 200 carrying PNG!
    png_sub = build_png_payload()
    frame20_sub = build_dbsf_v2_frame(png_sub, stream_id=200, fragment_index=0, fragment_count=1, payload_offset=0)
    nested_bmp = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(frame20_sub))

    zip_main20 = build_zip_payload("CASE20_OUTER_ZIP")
    pad_to_nested = 256 - len(zip_main20)
    assert pad_to_nested > 0
    outer_stream_payload = zip_main20 + os.urandom(pad_to_nested) + nested_bmp

    frame20_outer = build_dbsf_v2_frame(outer_stream_payload, stream_id=100, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp20_outer = build_bmp(width=130, height=130, bpp=24, bits_to_embed=frame_to_bits(frame20_outer))
    outer20 = os.urandom(4096) + bmp20_outer + os.urandom(1024)
    off20_outer = 4096

    p20 = out_path / "case20_recursive_nested.bin"
    p20.write_bytes(outer20)
    manifest.append({
        "id": "case20_recursive_nested",
        "file": p20.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 100,
            "carrier_offsets": [off20_outer],
            "total_payload_size": len(outer_stream_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}],
            "expected_nested_derived": [{
                "kind": "bmp-fragmented-stream",
                "stream_id": 200,
                "carrier_offsets": [256],
                "total_payload_size": len(png_sub),
                "expected_child_signatures": [{"name": "png", "offset": 0}]
            }]
        }],
        "description": "Recursive stream analysis: Stream 100 payload contains a nested BMP carrying Stream 200 with PNG"
    })

    # CASE 21: Decoy LSB stream: raw ZIP magic PK\x03\x04 without BWDERIV2 frame
    decoy_payload = b"PK\x03\x04" + os.urandom(20) + b"\x7fELF" + os.urandom(100)
    decoy_bits = []
    for b in decoy_payload:
        for shift in range(7, -1, -1):
            decoy_bits.append((b >> shift) & 1)
    bmp21 = build_bmp(width=60, height=40, bpp=24, bits_to_embed=decoy_bits)
    p21 = out_path / "case21_decoy_magic_no_frame.bin"
    p21.write_bytes(bmp21)
    manifest.append({
        "id": "case21_decoy_magic_no_frame",
        "file": p21.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Decoy LSB containing ZIP magic without BWDERIV2 frame must produce zero derived results"
    })

    # CASE 22: Oversized declared TotalLength = 0xFFFFFFFF
    frame22 = build_dbsf_v2_frame(b"dummy", stream_id=50, total_len=0xFFFFFFFF)
    bmp22 = build_bmp(width=40, height=30, bpp=24, bits_to_embed=frame_to_bits(frame22))
    p22 = out_path / "case22_oversized_stream.bin"
    p22.write_bytes(bmp22)
    manifest.append({
        "id": "case22_oversized_stream",
        "file": p22.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Declared TotalLength = 0xFFFFFFFF must safely reject without memory exhaustion or panic"
    })

    # CASE 23: Derived mode disabled: same file as Case 1, but with derived scanning OFF
    manifest.append({
        "id": "case23_derived_disabled",
        "file": p1.name,
        "enable_derived": False,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Derived scanning disabled (default); AnalysisResults.derived must be empty"
    })

    # CASE 24: Filter inheritance on reassembled stream
    zip_part = build_zip_payload("CASE24_FILTER_ZIP")
    png_part = build_png_payload()
    pad_len = 256 - len(zip_part)
    dual_payload = zip_part + os.urandom(pad_len) + png_part
    frame24 = build_dbsf_v2_frame(dual_payload, stream_id=60, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp24 = build_bmp(width=85, height=50, bpp=24, bits_to_embed=frame_to_bits(frame24))
    p24 = out_path / "case24_filter_inheritance.bin"
    p24.write_bytes(bmp24)
    manifest.append({
        "id": "case24_filter_include_zip",
        "file": p24.name,
        "enable_derived": True,
        "include": ["zip"],
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 60,
            "carrier_offsets": [0],
            "total_payload_size": len(dual_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}],
            "forbidden_child_signatures": ["png"]
        }],
        "description": "Filter inheritance: --include zip must include zip and omit png from derived child file_map"
    })
    manifest.append({
        "id": "case24_filter_exclude_zip",
        "file": p24.name,
        "enable_derived": True,
        "exclude": ["zip"],
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 60,
            "carrier_offsets": [0],
            "total_payload_size": len(dual_payload),
            "expected_child_signatures": [{"name": "png", "offset": 256}],
            "forbidden_child_signatures": ["zip"]
        }],
        "description": "Filter inheritance: --exclude zip must omit zip and keep png in derived child file_map"
    })

    # CASE 25: Leading stream offset: 64 bytes of random prefix data before DBSF v2 frame
    zip_payload = build_zip_payload("CASE25_LEADING_OFFSET")
    frame25 = build_dbsf_v2_frame(zip_payload, stream_id=70, fragment_index=0, fragment_count=1, payload_offset=0)
    prefix_noise = os.urandom(64)
    raw_stream25 = prefix_noise + frame25
    bmp25 = build_bmp(width=85, height=55, bpp=24, bits_to_embed=frame_to_bits(raw_stream25))
    p25 = out_path / "case25_leading_stream_offset.bin"
    p25.write_bytes(bmp25)
    manifest.append({
        "id": "case25_leading_stream_offset",
        "file": p25.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 70,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Carrier stream contains 64 bytes of leading noise before BWDERIV2 frame"
    })

    # CASE 26: Decoy candidate before genuine frame:
    # Offset 0 has fake BWDERIV2 with corrupt CRC; offset 128 has genuine frame
    zip_payload = build_zip_payload("CASE26_GENUINE_AFTER_DECOY")
    genuine_frame26 = build_dbsf_v2_frame(zip_payload, stream_id=80, fragment_index=0, fragment_count=1, payload_offset=0)
    fake_frame26 = build_dbsf_v2_frame(b"FAKE_DATA_BLOCK", stream_id=80, corrupt_frag_crc=True)
    pad26 = os.urandom(128 - len(fake_frame26)) if len(fake_frame26) < 128 else b""
    raw_stream26 = fake_frame26 + pad26 + genuine_frame26
    bmp26 = build_bmp(width=90, height=60, bpp=24, bits_to_embed=frame_to_bits(raw_stream26))
    p26 = out_path / "case26_decoy_preceding_valid_frame.bin"
    p26.write_bytes(bmp26)
    manifest.append({
        "id": "case26_decoy_preceding_valid_frame",
        "file": p26.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 80,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Corrupt decoy BWDERIV2 frame at offset 0 followed by genuine frame at offset 128"
    })

    # CASE 27: Stale revision stream session disambiguation:
    # Carrier 0 contains stale fragment (stream_id=55, total_crc=0xDEAD1111).
    # Carrier 1 & 2 contain active fragments (stream_id=55, total_crc=crc27_active).
    zip_payload = build_zip_payload("CASE27_ACTIVE_STREAM55")
    slices27 = split_payload_with_offsets(zip_payload, 2)
    crc27_active = binascii.crc32(zip_payload) & 0xFFFFFFFF
    len27_active = len(zip_payload)

    f27_stale = build_dbsf_v2_frame(
        slices27[0][1], stream_id=55, fragment_index=0, fragment_count=2,
        payload_offset=0, total_len=80, total_crc=0xDEAD1111
    )
    f27_0 = build_dbsf_v2_frame(
        slices27[0][1], stream_id=55, fragment_index=0, fragment_count=2,
        payload_offset=slices27[0][0], total_len=len27_active, total_crc=crc27_active
    )
    f27_1 = build_dbsf_v2_frame(
        slices27[1][1], stream_id=55, fragment_index=1, fragment_count=2,
        payload_offset=slices27[1][0], total_len=len27_active, total_crc=crc27_active
    )

    bmp27_stale = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f27_stale))
    bmp27_0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f27_0))
    bmp27_1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f27_1))

    outer27 = os.urandom(512) + bmp27_stale + os.urandom(1024) + bmp27_0 + os.urandom(1024) + bmp27_1 + os.urandom(512)
    off27_stale = 512
    off27_0 = off27_stale + len(bmp27_stale) + 1024
    off27_1 = off27_0 + len(bmp27_0) + 1024

    p27 = out_path / "case27_stale_revision_disambiguation.bin"
    p27.write_bytes(outer27)
    manifest.append({
        "id": "case27_stale_revision_disambiguation",
        "file": p27.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 55,
            "carrier_offsets": [off27_0, off27_1],
            "total_payload_size": len27_active,
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Stream session disambiguation: stale fragment with same stream_id must not discard active session"
    })

    # CASE 28: Nested multi-fragment stream:
    # Outer Stream 105 carries a payload containing 2 nested BMPs (at offsets 256 and 1500).
    png_payload = build_png_payload()
    slices28_sub = split_payload_with_offsets(png_payload, 2)
    crc28_sub = binascii.crc32(png_payload) & 0xFFFFFFFF
    len28_sub = len(png_payload)

    f28_sub0 = build_dbsf_v2_frame(slices28_sub[0][1], stream_id=250, fragment_index=0, fragment_count=2, payload_offset=slices28_sub[0][0], total_len=len28_sub, total_crc=crc28_sub)
    f28_sub1 = build_dbsf_v2_frame(slices28_sub[1][1], stream_id=250, fragment_index=1, fragment_count=2, payload_offset=slices28_sub[1][0], total_len=len28_sub, total_crc=crc28_sub)

    nested_bmp0 = build_bmp(width=40, height=25, bpp=24, bits_to_embed=frame_to_bits(f28_sub0))
    nested_bmp1 = build_bmp(width=40, height=25, bpp=24, bits_to_embed=frame_to_bits(f28_sub1))

    zip_main28 = build_zip_payload("CASE28_OUTER_ZIP")
    pad_to_n0 = 256 - len(zip_main28)
    pad_between_n = 1000
    outer28_payload = zip_main28 + os.urandom(pad_to_n0) + nested_bmp0 + os.urandom(pad_between_n) + nested_bmp1
    off_n0 = 256
    off_n1 = 256 + len(nested_bmp0) + pad_between_n

    f28_outer = build_dbsf_v2_frame(outer28_payload, stream_id=105, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp28_outer = build_bmp(width=160, height=160, bpp=24, bits_to_embed=frame_to_bits(f28_outer))
    outer28 = os.urandom(2048) + bmp28_outer + os.urandom(1024)

    p28 = out_path / "case28_nested_multi_fragment_stream.bin"
    p28.write_bytes(outer28)
    manifest.append({
        "id": "case28_nested_multi_fragment_stream",
        "file": p28.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 105,
            "carrier_offsets": [2048],
            "total_payload_size": len(outer28_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}],
            "expected_nested_derived": [{
                "kind": "bmp-fragmented-stream",
                "stream_id": 250,
                "carrier_offsets": [off_n0, off_n1],
                "total_payload_size": len28_sub,
                "expected_child_signatures": [{"name": "png", "offset": 0}]
            }]
        }],
        "description": "Nested stream itself is fragmented across two nested carriers inside outer payload"
    })

    # CASE 29: Firmware UI sprite atlas resource pool:
    zip_payload = build_zip_payload("CASE29_ATLAS_STREAM90")
    slices29 = split_payload_with_offsets(zip_payload, 2)
    crc29 = binascii.crc32(zip_payload) & 0xFFFFFFFF
    f29_0 = build_dbsf_v2_frame(slices29[0][1], stream_id=90, fragment_index=0, fragment_count=2, payload_offset=slices29[0][0], total_len=len(zip_payload), total_crc=crc29)
    f29_1 = build_dbsf_v2_frame(slices29[1][1], stream_id=90, fragment_index=1, fragment_count=2, payload_offset=slices29[1][0], total_len=len(zip_payload), total_crc=crc29)
    fake_f29 = build_dbsf_v2_frame(b"DECOY", stream_id=999, corrupt_frag_crc=True)

    bmp29_frag0 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f29_0))
    bmp29_frag1 = build_bmp(width=50, height=30, bpp=24, bits_to_embed=frame_to_bits(f29_1))
    bmp29_decoy = build_bmp(width=40, height=25, bpp=24, bits_to_embed=frame_to_bits(fake_f29))

    atlas_parts = []
    for _ in range(4):
        atlas_parts.append(os.urandom(512))
        atlas_parts.append(build_bmp(width=30, height=20, bpp=24))

    atlas_parts.append(os.urandom(1024))
    off29_frag0 = sum(len(p) for p in atlas_parts)
    atlas_parts.append(bmp29_frag0)

    for _ in range(4):
        atlas_parts.append(os.urandom(512))
        atlas_parts.append(build_bmp(width=30, height=20, bpp=24))

    atlas_parts.append(os.urandom(512))
    atlas_parts.append(bmp29_decoy)

    for _ in range(4):
        atlas_parts.append(os.urandom(512))
        atlas_parts.append(build_bmp(width=30, height=20, bpp=24))

    atlas_parts.append(os.urandom(1024))
    off29_frag1 = sum(len(p) for p in atlas_parts)
    atlas_parts.append(bmp29_frag1)
    atlas_parts.append(os.urandom(512))

    outer29 = b"".join(atlas_parts)
    p29 = out_path / "case29_sprite_atlas_resource_pool.bin"
    p29.write_bytes(outer29)
    manifest.append({
        "id": "case29_sprite_atlas_resource_pool",
        "file": p29.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 90,
            "carrier_offsets": [off29_frag0, off29_frag1],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Firmware resource atlas with 15 BMPs: 12 normal, 1 decoy, 2 genuine fragments of Stream 90"
    })
    # CASE 30: 16-bit BMP carrier with BI_BITFIELDS (RGB565 masks)
    # Masks: Red=0xF800 (bit 11), Green=0x07E0 (bit 5), Blue=0x001F (bit 0)
    zip_payload = build_zip_payload("CASE30_16BIT_BITFIELDS_RGB565")
    frame30 = build_dbsf_v2_frame(zip_payload, stream_id=65, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp30 = build_bmp(width=80, height=50, bpp=16, bits_to_embed=frame_to_bits(frame30), compression=3)
    p30 = out_path / "case30_single_frag_16bit_bitfields_rgb565.bin"
    p30.write_bytes(bmp30)
    manifest.append({
        "id": "case30_single_frag_16bit_bitfields_rgb565",
        "file": p30.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 65,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "16-bit BMP carrier with BI_BITFIELDS (RGB565 masks) requiring dynamic bitmask LSB extraction"
    })

    # CASE 31: Large firmware splash screen carrier (1024x768 24-bit, 2.36 million bits)
    # Dense 56-bit decoy storm (b"BWDERIV!") forcing naive loops to evaluate 56 consecutive bit matches
    # Requires performance-bounded O(1) bit-shift register preamble sync (penalizes naive O(N*64) nested loops)
    zip_payload = build_zip_payload("CASE31_LARGE_SPLASH_SCREEN_PAYLOAD")
    frame31 = build_dbsf_v2_frame(zip_payload, stream_id=95, fragment_index=0, fragment_count=1, payload_offset=0)
    
    # Craft dense near-match decoy noise (56 bits matching BWDERIV2, failing only at byte 7)
    decoy_prefix = b"BWDERIV!" * 12500  # 100,000 bytes = 800,000 bits of 56-bit near-match decoys!
    decoy_bits = []
    for b in decoy_prefix:
        for s in range(7, -1, -1):
            decoy_bits.append((b >> s) & 1)
    
    all_bits31 = decoy_bits + frame_to_bits(frame31)
    bmp31 = build_bmp(width=1024, height=768, bpp=24, bits_to_embed=all_bits31)
    p31 = out_path / "case31_large_firmware_splash_screen.bin"
    p31.write_bytes(bmp31)
    manifest.append({
        "id": "case31_large_firmware_splash_screen",
        "file": p31.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 95,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Large 800x480 splash screen carrier testing performance-bounded preamble synchronization"
    })

    # CASE 32: Unsupported RLE8 compressed BMP (biCompression == 1)
    # Must be gracefully ignored without crash or panic, yielding zero derived streams
    bmp32 = build_bmp(width=60, height=40, bpp=24, compression=1)
    p32 = out_path / "case32_unsupported_rle_bmp_graceful_ignore.bin"
    p32.write_bytes(bmp32)
    manifest.append({
        "id": "case32_unsupported_rle_bmp_graceful_ignore",
        "file": p32.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Unsupported RLE compressed BMP (BI_RLE8); must be gracefully ignored without errors"
    })

    # CASE 33: 16-bit BMP with BITMAPV4HEADER (108 bytes, embedded color masks at offset 40..52)
    # Requires internal mask resolution rather than trailing mask offset
    zip_payload33 = build_zip_payload("CASE33_V4_EMBEDDED_MASKS")
    frame33 = build_dbsf_v2_frame(zip_payload33, stream_id=133, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp33 = build_bmp(width=80, height=50, bpp=16, compression=3, dib_size=108, bits_to_embed=frame_to_bits(frame33))
    p33 = out_path / "case33_v4_header_embedded_masks.bin"
    p33.write_bytes(bmp33)
    manifest.append({
        "id": "case33_v4_header_embedded_masks",
        "file": p33.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 133,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload33),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "16-bit BMP with BITMAPV4HEADER (108 bytes, embedded color masks at offset 40..52); requires internal mask resolution rather than trailing mask offset"
    })

    # CASE 34: Malformed frame declaring zero-length payload (fragment_length == 0, total_length == 0)
    # Must be safely rejected without creating empty derived stream
    frame34 = build_dbsf_v2_frame(b"", stream_id=134, fragment_index=0, fragment_count=1, payload_offset=0, declared_frag_len=0, total_len=0)
    bmp34 = build_bmp(width=60, height=40, bpp=24, bits_to_embed=frame_to_bits(frame34))
    p34 = out_path / "case34_zero_length_payload_rejection.bin"
    p34.write_bytes(bmp34)
    manifest.append({
        "id": "case34_zero_length_payload_rejection",
        "file": p34.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Malformed frame declaring zero-length payload (fragment_length == 0, total_length == 0); must be safely rejected without creating empty derived stream"
    })

    # CASE 35: Two coexisting firmware revisions sharing identical (StreamId, TotalCRC) but differing TotalLength
    # Valid complete session must be disambiguated and recovered rather than grouped and aborted
    zip_rev1 = build_zip_payload("CASE35_VALID_REVISION_1")
    actual_crc1 = binascii.crc32(zip_rev1) & 0xFFFFFFFF
    frame_rev1 = build_dbsf_v2_frame(zip_rev1, stream_id=88, fragment_index=0, fragment_count=1, payload_offset=0, total_crc=actual_crc1)
    bmp35_rev1 = build_bmp(width=60, height=40, bpp=24, bits_to_embed=frame_to_bits(frame_rev1))
    
    frame_rev2 = build_dbsf_v2_frame(b"STALE_REV2_PART_0", stream_id=88, fragment_index=0, fragment_count=2, payload_offset=0, total_len=1024, total_crc=actual_crc1)
    bmp35_rev2 = build_bmp(width=60, height=40, bpp=24, bits_to_embed=frame_to_bits(frame_rev2))
    
    outer35 = os.urandom(1024) + bmp35_rev1 + os.urandom(512) + bmp35_rev2 + os.urandom(256)
    p35 = out_path / "case35_conflicting_revision_session_disambiguation.bin"
    p35.write_bytes(outer35)
    manifest.append({
        "id": "case35_conflicting_revision_session_disambiguation",
        "file": p35.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 88,
            "carrier_offsets": [1024],
            "total_payload_size": len(zip_rev1),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Two coexisting firmware revisions sharing identical (StreamId, TotalCRC) but differing TotalLength; valid complete session must be disambiguated and recovered"
    })

    # CASE 36: Malformed DBSF frame declaring total_length exceeding 16 MiB specification limit
    # Must be safely rejected without unbounded memory allocation
    frame36 = build_dbsf_v2_frame(b"A" * 50, stream_id=136, fragment_index=0, fragment_count=1, payload_offset=0, declared_frag_len=50, total_len=33554432)
    bmp36 = build_bmp(width=60, height=40, bpp=24, bits_to_embed=frame_to_bits(frame36))
    p36 = out_path / "case36_malformed_oversized_total_length.bin"
    p36.write_bytes(bmp36)
    manifest.append({
        "id": "case36_malformed_oversized_total_length",
        "file": p36.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Malformed DBSF frame declaring total_length exceeding 16 MiB specification limit; must be safely rejected without unbounded memory allocation"
    })

    # ===== Rev. C case families: cross-carrier bit splicing, containment, session instance rules =====

    # CASE 37: A single frame spliced across two carriers at a sub-byte bit phase.
    # Carrier A's entire sampled capacity is consumed mid-payload; the frame continues
    # at the very first sampled bit of carrier B with no re-alignment.
    zip_payload = build_zip_payload("CASE37_SPLICE_TWO_CARRIERS")
    frame37 = build_dbsf_v2_frame(zip_payload, stream_id=371, fragment_index=0, fragment_count=1, payload_offset=0)
    bits37 = frame_to_bits(frame37)
    wA, hA = dims_for_bits(len(bits37) // 2)
    capA = wA * hA * 3
    assert 384 < capA < len(bits37) and (capA % 8) != 0
    wB, hB = dims_for_bits(len(bits37) - capA)
    bmp37_a = build_bmp(width=wA, height=hA, bpp=24, bits_to_embed=bits37[:capA])
    bmp37_b = build_bmp(width=wB, height=hB, bpp=24, bits_to_embed=bits37[capA:])
    outer37 = os.urandom(256) + bmp37_a + os.urandom(128) + bmp37_b + os.urandom(64)
    off37_a = 256
    off37_b = 256 + len(bmp37_a) + 128
    p37 = out_path / "case37_splice_two_carrier_mid_payload.bin"
    p37.write_bytes(outer37)
    manifest.append({
        "id": "case37_splice_two_carrier_mid_payload",
        "file": p37.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 371,
            "carrier_offsets": [off37_a, off37_b],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Frame spliced across two carriers at sub-byte bit phase: carrier A consumed mid-payload, continuation at carrier B bit 0"
    })

    # CASE 38: Two-fragment stream; fragment 0 splices across a 24-bit bottom-up carrier
    # into a 32-bit top-down carrier; fragment 1 lives in a 16-bit RGB555 carrier.
    zip_payload = build_zip_payload("CASE38_TRISPLICE_MIXED_FORMATS")
    slices38 = split_payload_with_offsets(zip_payload, 2)
    crc38 = binascii.crc32(zip_payload) & 0xFFFFFFFF
    f38_0 = build_dbsf_v2_frame(slices38[0][1], stream_id=382, fragment_index=0, fragment_count=2, payload_offset=slices38[0][0], total_len=len(zip_payload), total_crc=crc38)
    f38_1 = build_dbsf_v2_frame(slices38[1][1], stream_id=382, fragment_index=1, fragment_count=2, payload_offset=slices38[1][0], total_len=len(zip_payload), total_crc=crc38)
    bits38_0 = frame_to_bits(f38_0)
    bits38_1 = frame_to_bits(f38_1)
    wA, hA = dims_for_bits(int(len(bits38_0) * 0.6))
    capA = wA * hA * 3
    assert 384 < capA < len(bits38_0) and (capA % 8) != 0
    wB, hB = dims_for_bits(len(bits38_0) - capA)
    wC, hC = dims_for_bits(len(bits38_1))
    bmp38_a = build_bmp(width=wA, height=hA, bpp=24, bits_to_embed=bits38_0[:capA])
    bmp38_b = build_bmp(width=wB, height=-hB, bpp=32, bits_to_embed=bits38_0[capA:])
    bmp38_c = build_bmp(width=wC, height=hC, bpp=16, bits_to_embed=bits38_1)
    outer38 = os.urandom(192) + bmp38_a + os.urandom(96) + bmp38_b + os.urandom(96) + bmp38_c + os.urandom(48)
    off38_a = 192
    off38_b = 192 + len(bmp38_a) + 96
    off38_c = off38_b + len(bmp38_b) + 96
    p38 = out_path / "case38_splice_three_carriers_mixed_formats.bin"
    p38.write_bytes(outer38)
    manifest.append({
        "id": "case38_splice_three_carriers_mixed_formats",
        "file": p38.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 382,
            "carrier_offsets": [off38_a, off38_b, off38_c],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Fragment 0 spliced across 24bpp bottom-up into 32bpp top-down carrier; fragment 1 in 16bpp RGB555 carrier"
    })

    # CASE 39: Frame spliced across two carriers with an 8-bit PALETTE BMP (unsupported,
    # contributes zero bits) sitting in the gap. The palette BMP carries a raw fake
    # BWDERIV2 header in its pixel bytes: implementations that sample raw bytes or
    # unqualified carriers must not produce anything.
    zip_payload = build_zip_payload("CASE39_PALETTE_GAP_SPLICE")
    frame39 = build_dbsf_v2_frame(zip_payload, stream_id=393, fragment_index=0, fragment_count=1, payload_offset=0)
    bits39 = frame_to_bits(frame39)
    wA, hA = dims_for_bits(int(len(bits39) * 0.3))
    capA = wA * hA * 3
    assert 384 < capA < len(bits39) and (capA % 8) != 0
    wB, hB = dims_for_bits(len(bits39) - capA)
    bmp39_a = build_bmp(width=wA, height=hA, bpp=24, bits_to_embed=bits39[:capA])
    bmp39_b = build_bmp(width=wB, height=hB, bpp=24, bits_to_embed=bits39[capA:])
    fake39_frame = build_dbsf_v2_frame(b"PALETTE-DECOY", stream_id=31337, corrupt_frag_crc=True)
    pal39 = build_palette_bmp(width=20, height=10, raw_decoy=fake39_frame)
    outer39 = os.urandom(160) + bmp39_a + os.urandom(80) + pal39 + os.urandom(80) + bmp39_b + os.urandom(64)
    off39_a = 160
    off39_b = 160 + len(bmp39_a) + 80 + len(pal39) + 80
    p39 = out_path / "case39_splice_over_palette_gap_decoy.bin"
    p39.write_bytes(outer39)
    manifest.append({
        "id": "case39_splice_over_palette_gap_decoy",
        "file": p39.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 393,
            "carrier_offsets": [off39_a, off39_b],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Splice across carriers with unsupported palette BMP (raw BWDERIV2 decoy) in the gap; palette contributes zero bits and must stay invisible"
    })

    # CASE 40: The 64-bit preamble itself is split across a carrier boundary: the first
    # 27 preamble bits are the entire sampled capacity of a 9x1 carrier, the remaining
    # 37 bits and the whole frame live in the next carrier. Carrier A contributes only
    # preamble bits but must still be listed in carrier_offsets.
    zip_payload = build_zip_payload("CASE40_PREAMBLE_SPLIT")
    frame40 = build_dbsf_v2_frame(zip_payload, stream_id=404, fragment_index=0, fragment_count=1, payload_offset=0)
    bits40 = frame_to_bits(frame40)
    K40 = 27
    assert 9 * 1 * 3 == K40
    bmp40_a = build_bmp(width=9, height=1, bpp=24, bits_to_embed=bits40[:K40])
    wB, hB = dims_for_bits(len(bits40) - K40)
    bmp40_b = build_bmp(width=wB, height=hB, bpp=24, bits_to_embed=bits40[K40:])
    outer40 = os.urandom(100) + bmp40_a + os.urandom(50) + bmp40_b + os.urandom(32)
    off40_a = 100
    off40_b = 100 + len(bmp40_a) + 50
    p40 = out_path / "case40_preamble_split_across_boundary.bin"
    p40.write_bytes(outer40)
    manifest.append({
        "id": "case40_preamble_split_across_boundary",
        "file": p40.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 404,
            "carrier_offsets": [off40_a, off40_b],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "BWDERIV2 preamble split 27/37 bits across carrier boundary; preamble-only carrier must appear in carrier_offsets"
    })

    # CASE 41: Frame opacity / containment. The genuine stream's payload contains a fully
    # valid, CRC-clean ghost frame (its own stream id 414). The ghost begins inside the
    # accepted frame's bit span and must never be interpreted as a frame start: exactly
    # one stream (411) may be reported.
    zip_payload = build_zip_payload("CASE41_CONTAINMENT_GHOST")
    ghost41 = build_dbsf_v2_frame(b"GHOST!", stream_id=414, fragment_index=0, fragment_count=1, payload_offset=0)
    real41_payload = zip_payload + os.urandom(50) + ghost41 + os.urandom(50)
    frame41 = build_dbsf_v2_frame(real41_payload, stream_id=411, fragment_index=0, fragment_count=1, payload_offset=0)
    w41, h41 = dims_for_bits(len(frame_to_bits(frame41)))
    bmp41 = build_bmp(width=w41, height=h41, bpp=24, bits_to_embed=frame_to_bits(frame41))
    p41 = out_path / "case41_nested_preamble_ghost_inside_payload.bin"
    p41.write_bytes(os.urandom(128) + bmp41 + os.urandom(64))
    manifest.append({
        "id": "case41_nested_preamble_ghost_inside_payload",
        "file": p41.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 411,
            "carrier_offsets": [128],
            "total_payload_size": len(real41_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Fully valid ghost frame embedded inside an accepted frame's payload; containment rule must suppress it (exactly one stream reported)"
    })

    # CASE 42: Byte-identical retransmission. Fragment 0 appears twice (identical bytes),
    # fragment 1 once: three physical instances for FragmentCount 2. The duplicate
    # instance invalidates the session even though every CRC would pass.
    zip_payload = build_zip_payload("CASE42_RETRANSMISSION")
    slices42 = split_payload_with_offsets(zip_payload, 2)
    crc42 = binascii.crc32(zip_payload) & 0xFFFFFFFF
    f42_0 = build_dbsf_v2_frame(slices42[0][1], stream_id=422, fragment_index=0, fragment_count=2, payload_offset=slices42[0][0], total_len=len(zip_payload), total_crc=crc42)
    f42_0_dup = build_dbsf_v2_frame(slices42[0][1], stream_id=422, fragment_index=0, fragment_count=2, payload_offset=slices42[0][0], total_len=len(zip_payload), total_crc=crc42)
    f42_1 = build_dbsf_v2_frame(slices42[1][1], stream_id=422, fragment_index=1, fragment_count=2, payload_offset=slices42[1][0], total_len=len(zip_payload), total_crc=crc42)
    assert f42_0 == f42_0_dup
    w42, h42 = dims_for_bits(len(frame_to_bits(f42_0)))
    bmp42_a = build_bmp(width=w42, height=h42, bpp=24, bits_to_embed=frame_to_bits(f42_0))
    bmp42_b = build_bmp(width=w42, height=h42, bpp=24, bits_to_embed=frame_to_bits(f42_0_dup))
    bmp42_c = build_bmp(width=w42, height=h42, bpp=24, bits_to_embed=frame_to_bits(f42_1))
    outer42 = os.urandom(96) + bmp42_a + os.urandom(64) + bmp42_b + os.urandom(64) + bmp42_c
    p42 = out_path / "case42_identical_retransmission_reject.bin"
    p42.write_bytes(outer42)
    manifest.append({
        "id": "case42_identical_retransmission_reject",
        "file": p42.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Byte-identical duplicate of fragment 0 raises physical instance count to 3 for FragmentCount 2; session must be rejected"
    })

    # CASE 43: Recursion depth boundary. Streams 941 -> 942 -> 943 -> 944 nest four levels
    # deep. Depths 1..3 (941, 942, 943) are reported; 944 is reachable only at depth 4
    # and must never appear.
    zip_d4 = build_zip_payload("CASE43_LEVEL_FOUR")
    f43_4 = build_dbsf_v2_frame(zip_d4, stream_id=944, fragment_index=0, fragment_count=1, payload_offset=0)
    w, h = dims_for_bits(len(frame_to_bits(f43_4)))
    carrier43_s = build_bmp(width=w, height=h, bpp=24, bits_to_embed=frame_to_bits(f43_4))

    zip_d3 = build_zip_payload("CASE43_LEVEL_THREE")
    payload43_r = zip_d3 + os.urandom(64) + carrier43_s
    off43_s_in_r = len(zip_d3) + 64
    f43_3 = build_dbsf_v2_frame(payload43_r, stream_id=943, fragment_index=0, fragment_count=1, payload_offset=0)
    w, h = dims_for_bits(len(frame_to_bits(f43_3)))
    carrier43_r = build_bmp(width=w, height=h, bpp=24, bits_to_embed=frame_to_bits(f43_3))

    zip_d2 = build_zip_payload("CASE43_LEVEL_TWO")
    payload43_q = zip_d2 + os.urandom(64) + carrier43_r
    off43_r_in_q = len(zip_d2) + 64
    f43_2 = build_dbsf_v2_frame(payload43_q, stream_id=942, fragment_index=0, fragment_count=1, payload_offset=0)
    w, h = dims_for_bits(len(frame_to_bits(f43_2)))
    carrier43_q = build_bmp(width=w, height=h, bpp=24, bits_to_embed=frame_to_bits(f43_2))

    zip_d1 = build_zip_payload("CASE43_LEVEL_ONE")
    payload43_p = zip_d1 + os.urandom(64) + carrier43_q
    off43_q_in_p = len(zip_d1) + 64
    f43_1 = build_dbsf_v2_frame(payload43_p, stream_id=941, fragment_index=0, fragment_count=1, payload_offset=0)
    w, h = dims_for_bits(len(frame_to_bits(f43_1)))
    bmp43_outer = build_bmp(width=w, height=h, bpp=24, bits_to_embed=frame_to_bits(f43_1))
    p43 = out_path / "case43_recursion_depth_four_boundary.bin"
    p43.write_bytes(os.urandom(128) + bmp43_outer + os.urandom(64))
    manifest.append({
        "id": "case43_recursion_depth_four_boundary",
        "file": p43.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 941,
            "carrier_offsets": [128],
            "total_payload_size": len(payload43_p),
            "expected_child_signatures": [{"name": "zip", "offset": 0}],
            "expected_nested_derived": [{
                "kind": "bmp-fragmented-stream",
                "stream_id": 942,
                "carrier_offsets": [off43_q_in_p],
                "total_payload_size": len(payload43_q),
                "expected_child_signatures": [{"name": "zip", "offset": 0}],
                "expected_nested_derived": [{
                    "kind": "bmp-fragmented-stream",
                    "stream_id": 943,
                    "carrier_offsets": [off43_r_in_q],
                    "total_payload_size": len(payload43_r),
                    "expected_child_signatures": [{"name": "zip", "offset": 0}],
                    "expected_nested_derived": []
                }]
            }]
        }],
        "description": "Four-level nesting: depths 1-3 reported (941>942>943), depth-4 stream 944 must not appear"
    })

    # CASE 44: Unknown NON-critical TLV records are parsed and ignored; the trailing
    # Cyclic XOR Key record still applies. hlen = 40 + 3 + 2 + 6 = 51.
    zip_payload = build_zip_payload("CASE44_NONCRITICAL_TLV_XOR")
    ext44 = build_tlv(0x42, b"\x00\x01") + build_tlv(0x07, b"\x2A")
    frame44 = build_dbsf_v2_frame(zip_payload, stream_id=444, fragment_index=0, fragment_count=1, payload_offset=0, header_ext=ext44, xor_key=b"\x11\x22\x33\x44")
    w44, h44 = dims_for_bits(len(frame_to_bits(frame44)))
    bmp44 = build_bmp(width=w44, height=h44, bpp=24, bits_to_embed=frame_to_bits(frame44))
    p44 = out_path / "case44_tlv_unknown_noncritical_accept.bin"
    p44.write_bytes(os.urandom(96) + bmp44)
    manifest.append({
        "id": "case44_tlv_unknown_noncritical_accept",
        "file": p44.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 444,
            "carrier_offsets": [96],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Unknown non-critical TLVs ignored while trailing XOR key TLV still descrambles; frame must be accepted"
    })

    # CASE 45: A complete, valid carrier (with a fully valid stream inside) is embedded
    # inside another carrier's pixel array. Discovery consumes the outer carrier's whole
    # byte extent, so the inner candidate must never be re-examined: zero derived results.
    zip_payload = build_zip_payload("CASE45_INNER_MUST_NOT_BE_SEEN")
    f45_inner = build_dbsf_v2_frame(zip_payload, stream_id=455, fragment_index=0, fragment_count=1, payload_offset=0)
    inner45 = build_bmp(width=40, height=25, bpp=24, bits_to_embed=frame_to_bits(f45_inner))
    host45 = bytearray(build_bmp(width=160, height=160, bpp=24))
    stride45 = ((160 * 24 + 31) // 32) * 4
    place45 = 54 + 10 * stride45 + 4
    assert place45 + len(inner45) < len(host45)
    host45[place45:place45 + len(inner45)] = inner45
    p45 = out_path / "case45_nested_bm_in_pixels_suppressed.bin"
    p45.write_bytes(bytes(host45))
    manifest.append({
        "id": "case45_nested_bm_in_pixels_suppressed",
        "file": p45.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Valid carrier embedded inside another carrier's consumed pixel array; greedy discovery must suppress it entirely"
    })

    # CASE 46: Two independent single-fragment streams hosted back-to-back in ONE carrier;
    # the second preamble begins exactly at the first frame's final bit. Both streams are
    # reported and both list the same carrier.
    z46a = build_zip_payload("CASE46_STREAM_ELEVEN")
    z46b = build_zip_payload("CASE46_STREAM_TWENTYTWO")
    f46a = build_dbsf_v2_frame(z46a, stream_id=4611, fragment_index=0, fragment_count=1, payload_offset=0)
    f46b = build_dbsf_v2_frame(z46b, stream_id=4622, fragment_index=0, fragment_count=1, payload_offset=0)
    bits46 = frame_to_bits(f46a) + frame_to_bits(f46b)
    w46, h46 = dims_for_bits(len(bits46))
    bmp46 = build_bmp(width=w46, height=h46, bpp=24, bits_to_embed=bits46)
    p46 = out_path / "case46_two_streams_single_carrier.bin"
    p46.write_bytes(os.urandom(64) + bmp46 + os.urandom(32))
    manifest.append({
        "id": "case46_two_streams_single_carrier",
        "file": p46.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [
            {
                "kind": "bmp-fragmented-stream",
                "stream_id": 4611,
                "carrier_offsets": [64],
                "total_payload_size": len(z46a),
                "expected_child_signatures": [{"name": "zip", "offset": 0}]
            },
            {
                "kind": "bmp-fragmented-stream",
                "stream_id": 4622,
                "carrier_offsets": [64],
                "total_payload_size": len(z46b),
                "expected_child_signatures": [{"name": "zip", "offset": 0}]
            }
        ],
        "description": "Two back-to-back streams share one carrier; second preamble starts at first frame's end bit"
    })

    # CASE 47: biSizeImage is not authoritative. Carrier declares biSizeImage == 0 while
    # the derived geometry (width/height/bpp/stride) is perfectly valid; the stream must
    # still be recovered.
    zip_payload = build_zip_payload("CASE47_BISIZEIMAGE_ZERO")
    frame47 = build_dbsf_v2_frame(zip_payload, stream_id=477, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp47 = build_bmp(width=70, height=40, bpp=24, bits_to_embed=frame_to_bits(frame47), bisize_image=0)
    p47 = out_path / "case47_bisizeimage_zero_accept.bin"
    p47.write_bytes(os.urandom(64) + bmp47)
    manifest.append({
        "id": "case47_bisizeimage_zero_accept",
        "file": p47.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 477,
            "carrier_offsets": [64],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Carrier declares biSizeImage=0; geometry derives from width/height/bpp/stride and the stream must be recovered"
    })

    # CASE 48: Truncated frame: carrier capacity ends 56 bits into the frame header. The
    # candidate must be safely rejected, and the valid stream in the following carrier
    # must still be recovered.
    zip_payload = build_zip_payload("CASE48_VALID_AFTER_TRUNCATED")
    frame48_trunc = build_dbsf_v2_frame(zip_payload, stream_id=488, fragment_index=0, fragment_count=1, payload_offset=0)
    bits48_trunc = frame_to_bits(frame48_trunc)
    bmp48_a = build_bmp(width=40, height=1, bpp=24, bits_to_embed=bits48_trunc[:120])
    zip48_ok = build_zip_payload("CASE48_GENUINE_STREAM")
    f48_ok = build_dbsf_v2_frame(zip48_ok, stream_id=489, fragment_index=0, fragment_count=1, payload_offset=0)
    w48, h48 = dims_for_bits(len(frame_to_bits(f48_ok)))
    bmp48_b = build_bmp(width=w48, height=h48, bpp=24, bits_to_embed=frame_to_bits(f48_ok))
    outer48 = os.urandom(64) + bmp48_a + os.urandom(64) + bmp48_b
    off48_b = 64 + len(bmp48_a) + 64
    p48 = out_path / "case48_truncated_frame_tail_reject.bin"
    p48.write_bytes(outer48)
    manifest.append({
        "id": "case48_truncated_frame_tail_reject",
        "file": p48.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 489,
            "carrier_offsets": [off48_b],
            "total_payload_size": len(zip48_ok),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Preamble completes but frame truncates at carrier capacity; rejected safely and following carrier's stream still recovered"
    })

    # CASE 49: With derived scanning disabled the serialized JSON must not contain a
    # 'derived' field at all (byte-identical to legacy behavior).
    zip_payload = build_zip_payload("CASE49_DISABLED_NO_FIELD")
    frame49 = build_dbsf_v2_frame(zip_payload, stream_id=499, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp49 = build_bmp(width=80, height=50, bpp=24, bits_to_embed=frame_to_bits(frame49))
    p49 = out_path / "case49_disabled_omits_derived_field.bin"
    p49.write_bytes(bmp49)
    manifest.append({
        "id": "case49_disabled_omits_derived_field",
        "file": p49.name,
        "enable_derived": False,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Derived scanning disabled: the 'derived' key must be absent from serialized output, not merely empty"
    })

    # ===== Rev D trap family: non-contiguous masks, V5, interleaving, boundary-exact, reserved =====

    # CASE 50: 16-bit BI_BITFIELDS with NON-CONTIGUOUS channel masks. Sampled bit is the
    # lowest set bit of each mask; contiguous-565 assumptions must fail.
    NONCONTIG_MASKS = (0x5B00, 0x02D8, 0x0035)
    zip_payload = build_zip_payload("CASE50_NONCONTIGUOUS_MASKS")
    frame50 = build_dbsf_v2_frame(zip_payload, stream_id=501, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp50 = build_bmp(width=46, height=24, bpp=16, compression=3, masks=NONCONTIG_MASKS, bits_to_embed=frame_to_bits(frame50))
    p50 = out_path / "case50_noncontiguous_bitfields.bin"
    p50.write_bytes(bmp50)
    manifest.append({
        "id": "case50_noncontiguous_bitfields",
        "file": p50.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 501,
            "carrier_offsets": [0],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "16bpp BI_BITFIELDS with non-contiguous masks (R=0x5B00 G=0x02D8 B=0x0035); sampled bit is lowest set bit of each mask"
    })

    # CASE 51: 32bpp with BI_BITFIELDS compression is an unsupported carrier; must yield nothing
    zip_payload = build_zip_payload("CASE51_32BPP_BITFIELDS_REJECT")
    frame51 = build_dbsf_v2_frame(zip_payload, stream_id=511, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp51 = build_bmp(width=40, height=25, bpp=32, compression=3, bits_to_embed=frame_to_bits(frame51))
    p51 = out_path / "case51_32bpp_bitfields_reject.bin"
    p51.write_bytes(bmp51)
    manifest.append({
        "id": "case51_32bpp_bitfields_reject",
        "file": p51.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "32bpp BI_BITFIELDS is not a qualified carrier; embedded bits must be invisible"
    })

    # CASE 52: Fragments of two different streams interleaved within ONE carrier
    z52a = build_zip_payload("CASE52_STREAM_ALPHA")
    z52b = build_zip_payload("CASE52_STREAM_BETA")
    crc52a = binascii.crc32(z52a) & 0xFFFFFFFF
    sa = split_payload_with_offsets(z52a, 2)
    f52_a0 = build_dbsf_v2_frame(sa[0][1], stream_id=521, fragment_index=0, fragment_count=2, payload_offset=sa[0][0], total_len=len(z52a), total_crc=crc52a)
    f52_a1 = build_dbsf_v2_frame(sa[1][1], stream_id=521, fragment_index=1, fragment_count=2, payload_offset=sa[1][0], total_len=len(z52a), total_crc=crc52a)
    f52_b = build_dbsf_v2_frame(z52b, stream_id=522, fragment_index=0, fragment_count=1, payload_offset=0)
    bits52 = frame_to_bits(f52_a0) + frame_to_bits(f52_b) + frame_to_bits(f52_a1)
    w52, h52 = dims_for_bits(len(bits52))
    bmp52 = build_bmp(width=w52, height=h52, bpp=24, bits_to_embed=bits52)
    p52 = out_path / "case52_interleaved_streams_single_carrier.bin"
    p52.write_bytes(os.urandom(80) + bmp52)
    manifest.append({
        "id": "case52_interleaved_streams_single_carrier",
        "file": p52.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [
            {
                "kind": "bmp-fragmented-stream",
                "stream_id": 521,
                "carrier_offsets": [80],
                "total_payload_size": len(z52a),
                "expected_child_signatures": [{"name": "zip", "offset": 0}]
            },
            {
                "kind": "bmp-fragmented-stream",
                "stream_id": 522,
                "carrier_offsets": [80],
                "total_payload_size": len(z52b),
                "expected_child_signatures": [{"name": "zip", "offset": 0}]
            }
        ],
        "description": "Fragments of stream 521 interleaved with stream 522 inside one carrier; both recovered, carrier listed once each"
    })

    # CASE 53: Frame whose final bit is exactly the final sampled bit of the final carrier
    z53 = build_zip_payload("CASE53_BOUNDARY_EXACT_END")
    while (44 + len(z53)) % 3 != 0:
        z53 += b"!"
    frame53 = build_dbsf_v2_frame(z53, stream_id=531, fragment_index=0, fragment_count=1, payload_offset=0)
    bits53 = frame_to_bits(frame53)
    # Carrier A: 130x1 24bpp -> 390 bits (>= preamble+header, non-multiple of 8)
    capA53 = 130 * 1 * 3
    assert capA53 == 390 and capA53 % 8 != 0 and capA53 > 44 * 8
    rem53 = len(bits53) - capA53
    assert rem53 % 6 == 0
    bmp53_a = build_bmp(width=130, height=1, bpp=24, bits_to_embed=bits53[:capA53])
    bmp53_b = build_bmp(width=rem53 // 6, height=2, bpp=24, bits_to_embed=bits53[capA53:])
    outer53 = os.urandom(72) + bmp53_a + os.urandom(48) + bmp53_b
    off53_a = 72
    off53_b = 72 + len(bmp53_a) + 48
    p53 = out_path / "case53_frame_ends_at_bitstream_end.bin"
    p53.write_bytes(outer53)
    manifest.append({
        "id": "case53_frame_ends_at_bitstream_end",
        "file": p53.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 531,
            "carrier_offsets": [off53_a, off53_b],
            "total_payload_size": len(z53),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Spliced frame terminates exactly at the last sampled bit of the last carrier; must be accepted, not rejected as truncated"
    })

    # CASE 54: 16bpp BITMAPV5HEADER (124 bytes) with embedded BI_BITFIELDS masks
    zip_payload = build_zip_payload("CASE54_V5_EMBEDDED_MASKS")
    frame54 = build_dbsf_v2_frame(zip_payload, stream_id=541, fragment_index=0, fragment_count=1, payload_offset=0)
    bmp54 = build_bmp(width=44, height=22, bpp=16, compression=3, dib_size=124, bits_to_embed=frame_to_bits(frame54))
    p54 = out_path / "case54_v5_header_embedded_masks.bin"
    p54.write_bytes(os.urandom(64) + bmp54)
    manifest.append({
        "id": "case54_v5_header_embedded_masks",
        "file": p54.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 541,
            "carrier_offsets": [64],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "BITMAPV5HEADER carrier with embedded color masks; mask resolution must use header-internal fields"
    })

    # CASE 55: Reserved core field non-zero -> frame rejected
    zip_payload = build_zip_payload("CASE55_RESERVED_NONZERO")
    frame55 = build_dbsf_v2_frame(zip_payload, stream_id=551, fragment_index=0, fragment_count=1, payload_offset=0, reserved=1)
    w55, h55 = dims_for_bits(len(frame_to_bits(frame55)))
    bmp55 = build_bmp(width=w55, height=h55, bpp=24, bits_to_embed=frame_to_bits(frame55))
    p55 = out_path / "case55_reserved_nonzero_reject.bin"
    p55.write_bytes(bmp55)
    manifest.append({
        "id": "case55_reserved_nonzero_reject",
        "file": p55.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Core header reserved field is non-zero; frame must be rejected"
    })

    # CASE 56: Unknown non-critical TLV extension WITHOUT any descrambling key; accepted
    zip_payload = build_zip_payload("CASE56_NONCRITICAL_NO_KEY")
    ext56 = build_tlv(0x33, b"\x01\x02\x03") + build_tlv(0x2A, b"XYZW")
    frame56 = build_dbsf_v2_frame(zip_payload, stream_id=561, fragment_index=0, fragment_count=1, payload_offset=0, header_ext=ext56)
    w56, h56 = dims_for_bits(len(frame_to_bits(frame56)))
    bmp56 = build_bmp(width=w56, height=h56, bpp=24, bits_to_embed=frame_to_bits(frame56))
    p56 = out_path / "case56_noncritical_tlv_no_key.bin"
    p56.write_bytes(os.urandom(48) + bmp56)
    manifest.append({
        "id": "case56_noncritical_tlv_no_key",
        "file": p56.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 561,
            "carrier_offsets": [48],
            "total_payload_size": len(zip_payload),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Unknown non-critical TLV records with no key present; frame accepted unchanged"
    })
    stream_payloads = {}
    for (sid, fcnt, tlen, tcrc), fdict in _STREAM_FRAGS.items():
        if 0 < tlen <= 16 * 1024 * 1024 and len(fdict) == fcnt and all(i in fdict for i in range(fcnt)):
            buf = bytearray(tlen)
            ok = True
            for i in range(fcnt):
                poff, fdata = fdict[i]
                if poff + len(fdata) <= tlen:
                    buf[poff:poff + len(fdata)] = fdata
                else:
                    ok = False
            if ok and (binascii.crc32(buf) & 0xFFFFFFFF) == tcrc:
                stream_payloads[(sid, tlen)] = bytes(buf)

    def _enrich_stream_spec(stream_spec, include_filters=None):
        stream_spec["stream_id"] ^= _STREAM_ID_MASK
        sid = stream_spec["stream_id"]
        tlen = stream_spec["total_payload_size"]
        raw_payload = stream_payloads.get((sid, tlen))
        if raw_payload is None:
            raise RuntimeError(f'No complete reference payload for stream {sid}, length {tlen}')
        if raw_payload is not None:
            stream_spec["expected_payload_sha256"] = hashlib.sha256(raw_payload).hexdigest()
            for exp_sig in stream_spec.get("expected_child_signatures", []):
                soff = exp_sig["offset"]
                sname = exp_sig["name"]
                for btype, full_blob, inner_size, inner_sha in _PAYLOAD_BLOBS:
                    if btype == sname and raw_payload[soff:soff + len(full_blob)] == full_blob:
                        exp_sig["size"] = inner_size
                        exp_sig["description_contains"] = f"total size: {inner_size} bytes"
                        if include_filters != ["zip"]:
                            exp_sig["expected_content_sha256"] = inner_sha
                            exp_sig["expected_sha256_offset"] = soff + inner_size
                        break
        for nested in stream_spec.get("expected_nested_derived", []):
            _enrich_stream_spec(nested, include_filters)

    for case_entry in manifest:
        inc = case_entry.get("include")
        for s_spec in case_entry.get("expected_streams", []):
            _enrich_stream_spec(s_spec, inc)

    # Filenames never identify a test family to the submitted library. Shared
    # inputs (e.g. include/exclude variants) retain the same randomized name.
    renamed = {}
    for case_entry in manifest:
        original = case_entry['file']
        if original not in renamed:
            replacement = secrets.token_hex(16) + '.bin'
            (out_path / original).rename(out_path / replacement)
            renamed[original] = replacement
        case_entry['file'] = renamed[original]

    manifest_path = out_path / "cases_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"Generated {len(manifest)} test case entries in {out_path}")
    _RANDOMIZE = False
    _STREAM_ID_MASK = 0
if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/dbsf_v2_fixtures"
    generate_all_cases(out_dir)
