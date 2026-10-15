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

    # CASE 57: empty unknown noncritical TLV + maximum legal XOR key, unaligned.
    z57 = build_zip_payload("CASE57_EMPTY_TLV_MAX_KEY")
    ext57 = build_tlv(0x22, b"") + build_tlv(0x33, b"\x01")
    f57 = build_dbsf_v2_frame(z57, stream_id=571, header_ext=ext57,
                              xor_key=bytes(range(1, 17)))
    bits57 = frame_to_bits(f57)
    w57, h57 = dims_for_bits(len(bits57) + 3)
    bmp57 = build_bmp(width=w57, height=h57, bpp=24,
                      bits_to_embed=bits57, slip_bits=3)
    p57 = out_path / "case57_empty_tlv_xor16_bitphase.bin"
    p57.write_bytes(os.urandom(80) + bmp57)
    manifest.append({
        "id": "case57_empty_tlv_xor16_bitphase",
        "file": p57.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 571,
            "carrier_offsets": [80],
            "total_payload_size": len(z57),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Empty unknown noncritical TLV, maximal 16-byte XOR key, 3-bit sync slip"
    })

    # CASE 58: invalid 17-byte XOR key candidate must not suppress valid later frame.
    z58 = build_zip_payload("CASE58_AFTER_INVALID_KEY")
    invalid58 = build_dbsf_v2_frame(
        b"UNTRUSTED", stream_id=581, xor_key=bytes(range(1, 18)))
    valid58 = build_dbsf_v2_frame(z58, stream_id=582)
    bits58 = frame_to_bits(invalid58 + os.urandom(7) + valid58)
    w58, h58 = dims_for_bits(len(bits58))
    bmp58 = build_bmp(width=w58, height=h58, bpp=24, bits_to_embed=bits58)
    p58 = out_path / "case58_invalid_key_then_valid.bin"
    p58.write_bytes(os.urandom(64) + bmp58)
    manifest.append({
        "id": "case58_invalid_key_then_valid",
        "file": p58.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 582,
            "carrier_offsets": [64],
            "total_payload_size": len(z58),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "Reject 17-byte XOR key and continue synchronizing to next valid frame"
    })

    # CASE 59: two complete sessions share StreamId/CRC/length but differ in fragment count.
    z59 = build_zip_payload("CASE59_SAME_ID_CRC_DIFFERENT_FRAGMENT_COUNT")
    crc59 = binascii.crc32(z59) & 0xFFFFFFFF
    full59 = build_dbsf_v2_frame(z59, stream_id=591, fragment_count=1,
                                 total_len=len(z59), total_crc=crc59)
    slices59 = split_payload_with_offsets(z59, 2)
    part59_0 = build_dbsf_v2_frame(
        slices59[0][1], stream_id=591, fragment_index=0, fragment_count=2,
        payload_offset=slices59[0][0], total_len=len(z59), total_crc=crc59)
    part59_1 = build_dbsf_v2_frame(
        slices59[1][1], stream_id=591, fragment_index=1, fragment_count=2,
        payload_offset=slices59[1][0], total_len=len(z59), total_crc=crc59)
    bmps59 = []
    for framed in (full59, part59_1, part59_0):
        sample_bits = frame_to_bits(framed)
        wi, hi = dims_for_bits(len(sample_bits))
        bmps59.append(build_bmp(width=wi, height=hi, bpp=24, bits_to_embed=sample_bits))
    off59_a = 48
    off59_b = off59_a + len(bmps59[0]) + 32
    off59_c = off59_b + len(bmps59[1]) + 32
    p59 = out_path / "case59_same_id_crc_distinct_sessions.bin"
    p59.write_bytes(os.urandom(off59_a) + bmps59[0] + os.urandom(32)
                    + bmps59[1] + os.urandom(32) + bmps59[2])
    manifest.append({
        "id": "case59_same_id_crc_distinct_sessions",
        "file": p59.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 591,
            "carrier_offsets": [off59_a],
            "total_payload_size": len(z59),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }, {
            "kind": "bmp-fragmented-stream",
            "stream_id": 591,
            "carrier_offsets": [off59_b, off59_c],
            "total_payload_size": len(z59),
            "expected_child_signatures": [{"name": "zip", "offset": 0}]
        }],
        "description": "StreamId/CRC/length collision: distinct 1-fragment and 2-fragment sessions coexist"
    })

    # ===== Negative-carrier family: out-of-contract BMP variants must NEVER yield derived output =====

    # CASE 60: negative height (top-down) 24-bit BMP carrying a fully valid DBSF frame.
    # Top-down carriers are out of contract; the frame must be silently ignored.
    z60 = build_zip_payload("CASE60_NEGATIVE_HEIGHT_REJECTED")
    frame60 = build_dbsf_v2_frame(z60, stream_id=601)
    bits60 = frame_to_bits(frame60)
    w60, h60 = dims_for_bits(len(bits60))
    bmp60_topdown = build_bmp(width=w60, height=-h60, bpp=24, bits_to_embed=bits60)
    p60 = out_path / "case60_negative_height_rejected.bin"
    p60.write_bytes(os.urandom(32) + bmp60_topdown)
    manifest.append({
        "id": "case60_negative_height_rejected",
        "file": p60.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "Negative-height (top-down) BMP is out of contract; valid DBSF inside must be ignored"
    })

    # CASE 61: 16-bit BMP carrying DBSF bits. 16 bpp is out of contract.
    z61 = build_zip_payload("CASE61_16BPP_REJECTED")
    frame61 = build_dbsf_v2_frame(z61, stream_id=611)
    bits61 = frame_to_bits(frame61)
    w61, h61 = dims_for_bits(len(bits61))
    # 16bpp: embed one bit per channel via RGB555 LSBs; reuse masks default (0x7C00/0x03E0/0x001F)
    bmp61_16 = build_bmp(width=w61, height=h61, bpp=16, bits_to_embed=bits61, masks=(0x7C00, 0x03E0, 0x001F))
    p61 = out_path / "case61_16bpp_rejected.bin"
    p61.write_bytes(os.urandom(32) + bmp61_16)
    manifest.append({
        "id": "case61_16bpp_rejected",
        "file": p61.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "16-bit BMP is out of contract; sampled bits must never be interpreted"
    })

    # CASE 62: 32-bit BMP carrying DBSF bits with randomized alpha LSBs. Out of contract.
    z62 = build_zip_payload("CASE62_32BPP_REJECTED")
    frame62 = build_dbsf_v2_frame(z62, stream_id=621)
    bits62 = frame_to_bits(frame62)
    w62, h62 = dims_for_bits(len(bits62))
    bmp62_32 = build_bmp(width=w62, height=h62, bpp=32, bits_to_embed=bits62)
    p62 = out_path / "case62_32bpp_rejected.bin"
    p62.write_bytes(os.urandom(32) + bmp62_32)
    manifest.append({
        "id": "case62_32bpp_rejected",
        "file": p62.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "32-bit BMP is out of contract even with random alpha LSBs"
    })

    # CASE 63: BITMAPV5HEADER (124-byte DIB) 24-bit BMP carrying a valid frame. Out of contract.
    z63 = build_zip_payload("CASE63_V5HEADER_REJECTED")
    frame63 = build_dbsf_v2_frame(z63, stream_id=631)
    bits63 = frame_to_bits(frame63)
    w63, h63 = dims_for_bits(len(bits63))
    bmp63_v5 = build_bmp(width=w63, height=h63, bpp=24, bits_to_embed=bits63, dib_size=124)
    p63 = out_path / "case63_v5header_rejected.bin"
    p63.write_bytes(os.urandom(32) + bmp63_v5)
    manifest.append({
        "id": "case63_v5header_rejected",
        "file": p63.name,
        "enable_derived": True,
        "expect_derived": False,
        "expected_streams": [],
        "description": "BITMAPV5HEADER carriers are out of contract; only 40-byte INFOHEADER qualifies"
    })

    # CASE 64: nested ghost - a second valid DBSF frame embedded INSIDE a recovered
    # payload. Top-level scanning only: the inner frame must never yield a stream.
    z64_outer = build_zip_payload("CASE64_TOPLEVEL_PAYLOAD")
    z64_inner = build_zip_payload("CASE64_INNER_GHOST_MUST_IGNORE")
    frame64_inner = build_dbsf_v2_frame(z64_inner, stream_id=642)
    # Compose outer payload: inner frame bytes planted mid-payload
    composed64 = z64_outer[:64] + frame64_inner + z64_outer[64:]
    frame64_outer = build_dbsf_v2_frame(composed64, stream_id=641)
    bits64 = frame_to_bits(frame64_outer)
    w64, h64 = dims_for_bits(len(bits64))
    bmp64 = build_bmp(width=w64, height=h64, bpp=24, bits_to_embed=bits64)
    p64 = out_path / "case64_nested_ghost_rejected.bin"
    p64.write_bytes(os.urandom(24) + bmp64)
    manifest.append({
        "id": "case64_nested_ghost_rejected",
        "file": p64.name,
        "enable_derived": True,
        "expect_derived": True,
        "expected_streams": [{
            "kind": "bmp-fragmented-stream",
            "stream_id": 641,
            "carrier_offsets": [24],
            "total_payload_size": len(composed64),
            "expected_child_signatures": [{"name": "zip", "offset": 0}],
            "forbidden_child_signatures": [],
            "expected_stream_count_exact": 1
        }],
        "description": "DBSF frame inside a recovered payload must never produce a second derived stream (top-level only)"
    })

    stream_payloads = {}
    for (sid, fcnt, tlen, tcrc), fdict in _STREAM_FRAGS.items():
        if len(fdict) == fcnt and all(i in fdict for i in range(fcnt)):
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
            stream_spec["expected_payload_bytes"] = len(raw_payload)
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
