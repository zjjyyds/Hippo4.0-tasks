# TCP Evidence Reconstruction in D4 Network Forensics Suite

D4 Network Forensics Suite (`firmware/net_forensics.py`) parses PCAP files, tracks network flows, and extracts IoCs, but currently lacks forensic evidence reconstruction for TCP streams. In digital forensics and network intrusion analysis, reconstructing application data from captured packets requires strict adherence to evidence consistency: disputed or conflicting data must be explicitly identified rather than arbitrarily resolved.

Enhance `NetworkForensics.full_analysis()` in `firmware/net_forensics.py` to populate a `"tcp_evidence"` field in its returned summary dictionary.

## Functional Requirements

### 1. Per-Connection Stream Reconstruction
TCP traffic must be analyzed per directional connection identified by the 4-tuple:
`src_ip`, `sport`, `dst_ip`, `dport`.

### 2. Generational Lifetime Isolation
A single 4-tuple may be reused across multiple connection lifetimes (generations). Connections begin with a SYN handshake packet (or the earliest observed sequence when SYN is absent) and terminate upon FIN completion or RST. If a subsequent connection lifecycle is observed on the same 4-tuple, it must be tracked as an independent generation (`generation: 0, 1, ...`). Data from an earlier connection generation must never leak into or merge with a subsequent generation.

### 3. Circular Sequence Space
TCP sequence numbers are 32-bit unsigned integers modulo $2^{32}$. Stream reconstruction must correctly handle sequence wrap-around across the $2^{32}-1 \to 0$ boundary.

### 4. Sequence Space Consumption
TCP SYN and FIN control flags each consume one unit of sequence space. The application data payload starts at `ISN + 1`.

### 5. Payload Boundary and Link Padding
Ethernet frames enforce a minimum payload length (typically 60 bytes of MAC payload, 64 bytes total). Trailing frame padding often extends beyond the true IP packet. The genuine application payload must be bounded by the IPv4 Total Length, IP Header Length (IHL), and TCP Data Offset. Link-layer padding bytes must not be included in reconstructed TCP stream evidence.

### 6. Forensic Evidence Consistency and Conflict Handling
In forensics, overlapping or retransmitted segments that present conflicting bytes for the same logical sequence offset represent disputed evidence:
- Conflicting bytes must not be resolved by majority voting, arrival order, or overwriting.
- Any payload byte position where multiple observed packets disagree must be designated as an indeterminate byte represented by ASCII character `'?'` (`0x3F`) in the confirmed payload string.
- Positions where all observed packets agree are confirmed.
- Gaps between non-contiguous observed sequence ranges must be reported in `gaps` as 0-indexed relative payload offset ranges `[start_offset, end_offset]`.
- All conflicting byte offsets and their observed unique byte values (sorted) must be recorded in `conflicts`.

### 7. Output Contract
The dictionary returned by `NetworkForensics.full_analysis()` must include a `"tcp_evidence"` list. Entries must be sorted by `(src_ip, sport, dst_ip, dport, generation)` and adhere to the following schema:

```json
{
  "connection": {
    "src_ip": "192.168.1.100",
    "sport": 40001,
    "dst_ip": "10.0.0.1",
    "dport": 80
  },
  "generation": 0,
  "confirmed": "ABC?EF",
  "gaps": [[10, 15]],
  "conflicts": [
    {
      "offset": 3,
      "observed": ["D", "X"]
    }
  ],
  "total_observed_bytes": 6,
  "unambiguous_bytes": 5
}
```

- `confirmed`: ASCII/Latin-1 string of all observed bytes from payload offset 0 to the maximum observed sequence offset, using `'?'` at any conflict position and for unobserved gaps within the observed span.
- `gaps`: List of `[start, end]` ranges (half-open, 0-indexed relative to stream payload) for missing bytes within the stream.
- `conflicts`: List of conflict records sorted by `offset`, each containing `offset` (int) and `observed` (list of unique single-character strings sorted lexicographically).
- `total_observed_bytes`: Integer count of the total logical sequence byte span.
- `unambiguous_bytes`: Integer count of confirmed bytes that have no conflict.

### 8. Existing Behavior Compatibility
All pre-existing keys and outputs of `full_analysis()` (`file`, `total_packets`, `flows`, `protocol_analysis`, `iocs`, `top_talkers`, `timestamp_range`) must remain unchanged, and all upstream unit tests must continue to pass. Do not introduce external runtime dependencies.
