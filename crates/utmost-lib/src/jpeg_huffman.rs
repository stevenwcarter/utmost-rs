//! JPEG Huffman validation for recovery candidate ranking.
//!
//! Provides two layers of JPEG scan data validation used by the fragment
//! recovery engine to rank continuation candidates:
//!
//! - **Layer 1** ([`ff_byte_validity_score`]): Fast FF-byte pattern check.
//!   In valid JPEG scan data every `0xFF` must be followed by `0x00`,
//!   `0xD0–0xD7`, or `0xD9`.  Returns the fraction of FF bytes that comply.
//!
//! - **Layer 2** ([`parse_huffman_context`] + [`count_valid_mcus`]): Parse the
//!   Huffman tables from the JPEG header fragment, then attempt to decode the
//!   scan data and count successfully decoded MCUs.  Different images have
//!   different Huffman tables, so a wrong continuation block fails almost
//!   immediately.

// ── Layer 1: FF-byte pattern validation ──────────────────────────────────────

/// Score a byte slice by the fraction of `0xFF` bytes that are followed by a
/// byte valid inside JPEG scan data: `0x00` (byte-stuffing), `0xD0–0xD7`
/// (restart markers), or `0xD9` (EOI).
///
/// Returns `1.0` when the slice contains no `0xFF` bytes (can't be judged).
/// Returns `0.0` when every `0xFF` is followed by an invalid byte.
pub fn ff_byte_validity_score(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 1.0;
    }
    let mut ff_count = 0usize;
    let mut valid_count = 0usize;
    let mut i = 0;
    while i < data.len() - 1 {
        if data[i] == 0xFF {
            ff_count += 1;
            match data[i + 1] {
                0x00 | 0xD0..=0xD7 | 0xD9 => valid_count += 1,
                _ => {}
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    if ff_count == 0 {
        1.0
    } else {
        valid_count as f64 / ff_count as f64
    }
}

// ── Layer 2: Huffman context + MCU decode ─────────────────────────────────────

/// A single Huffman decode table built from a JPEG DHT segment.
struct HuffmanTable {
    /// For each bit length 1..=16: min code value at that length.
    min_code: [u16; 17],
    /// For each bit length 1..=16: max code value at that length.  `-1`
    /// means no codes of this length exist.
    max_code: [i32; 17],
    /// For each bit length 1..=16: index into `symbols` for the first code.
    val_ptr: [i32; 17],
    /// Symbols in canonical Huffman order.
    symbols: Vec<u8>,
}

impl HuffmanTable {
    /// Construct from the raw DHT payload: 16 code-count bytes followed by
    /// the symbol list.  Returns `None` for malformed payloads.
    fn from_dht_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < 16 {
            return None;
        }
        // Counts: payload[0..16] gives number of codes of length 1..=16.
        let counts = &payload[..16];
        let total_symbols: usize = counts.iter().map(|&c| c as usize).sum();
        if payload.len() < 16 + total_symbols {
            return None;
        }
        let symbols: Vec<u8> = payload[16..16 + total_symbols].to_vec();

        let mut min_code = [0u16; 17];
        let mut max_code = [-1i32; 17];
        let mut val_ptr = [0i32; 17];

        let mut code = 0u16;
        let mut sym_idx = 0i32;
        for len in 1usize..=16 {
            let count = counts[len - 1] as usize;
            if count > 0 {
                min_code[len] = code;
                max_code[len] = (code as i32) + (count as i32) - 1;
                val_ptr[len] = sym_idx - code as i32;
            }
            sym_idx += count as i32;
            code = code.wrapping_add(count as u16).wrapping_shl(1);
        }

        Some(HuffmanTable {
            min_code,
            max_code,
            val_ptr,
            symbols,
        })
    }
}

/// Per-component scan information extracted from SOS.
#[derive(Clone)]
struct ScanComponent {
    dc_table_idx: usize,
    ac_table_idx: usize,
    /// Horizontal × vertical sampling factors (from SOF).
    h_samp: u8,
    v_samp: u8,
}

/// All Huffman tables and scan-component information parsed from a JPEG header.
pub struct JpegHuffmanContext {
    /// Up to 4 tables indexed by `(class << 1) | destination_id`.
    /// Class 0 = DC, class 1 = AC.  Indices 0/1 = DC table 0/1, 2/3 = AC 0/1.
    tables: [Option<HuffmanTable>; 4],
    /// Ordered scan components as they appear in the SOS segment.
    components: Vec<ScanComponent>,
}

/// Attempt to parse Huffman tables (DHT segments) and scan-component
/// assignments (SOS segment) from a JPEG header fragment.
///
/// Returns `None` when:
/// - The header is too short or malformed to extract complete tables.
/// - No DHT segments are present.
/// - The JPEG uses progressive encoding (SOF2 marker `0xC2`) — graceful
///   fallback, since progressive scan data uses a different decode path.
pub fn parse_huffman_context(header_fragment: &[u8]) -> Option<JpegHuffmanContext> {
    let buf = header_fragment;
    if buf.len() < 10 {
        return None;
    }
    // Must start with SOI FF D8.
    if buf[0] != 0xFF || buf[1] != 0xD8 {
        return None;
    }

    let mut tables: [Option<HuffmanTable>; 4] = [None, None, None, None];
    // SOF component descriptors: component_id → (h_samp, v_samp).
    let mut sof_components: std::collections::HashMap<u8, (u8, u8)> = Default::default();
    let mut is_progressive = false;
    let mut scan_components: Vec<ScanComponent> = Vec::new();
    let mut found_dht = false;
    let mut found_sos = false;

    let mut pos = 2usize;
    loop {
        if pos + 4 > buf.len() {
            break;
        }
        if buf[pos] != 0xFF {
            break;
        }
        // Skip padding FF bytes.
        while pos + 1 < buf.len() && buf[pos + 1] == 0xFF {
            pos += 1;
        }
        if pos + 2 > buf.len() {
            break;
        }
        let marker = buf[pos + 1];
        pos += 2;

        match marker {
            0xD8 => continue, // SOI (nested) — skip
            0xD9 => break,    // EOI — stop

            0xDA => {
                // SOS — parse component-table assignments, then stop.
                if pos + 2 > buf.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                if seg_len < 3 || pos + seg_len > buf.len() {
                    break;
                }
                let ns = buf[pos + 2] as usize; // number of scan components
                if seg_len < 2 + 1 + ns * 2 {
                    break;
                }
                for i in 0..ns {
                    let comp_id = buf[pos + 3 + i * 2];
                    let table_byte = buf[pos + 4 + i * 2];
                    let dc_tbl = (table_byte >> 4) as usize;
                    let ac_tbl = (table_byte & 0x0F) as usize;
                    if dc_tbl > 1 || ac_tbl > 1 {
                        // Only two DC and two AC tables defined in baseline.
                        break;
                    }
                    let (h_samp, v_samp) = sof_components.get(&comp_id).copied().unwrap_or((1, 1));
                    scan_components.push(ScanComponent {
                        dc_table_idx: dc_tbl,
                        ac_table_idx: ac_tbl + 2, // AC tables occupy slots 2 and 3
                        h_samp,
                        v_samp,
                    });
                }
                found_sos = true;
                break;
            }

            _ => {
                // All other segments have a big-endian length field.
                if pos + 2 > buf.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                if seg_len < 2 || pos + seg_len > buf.len() {
                    break;
                }

                match marker {
                    0xC2 => {
                        // SOF2 = progressive — bail out.
                        is_progressive = true;
                    }
                    0xC0 | 0xC1 => {
                        // SOF0 / SOF1 (baseline / extended sequential)
                        // Layout after FF Cx [len_hi len_lo]:
                        //   precision(1) height(2) width(2) ncomponents(1)
                        //   [comp_id(1) samp_factors(1) qtable(1)] × ncomponents
                        if pos + 8 <= buf.len() {
                            let ncomp = buf[pos + 5] as usize;
                            if pos + 6 + ncomp * 3 <= buf.len() {
                                for i in 0..ncomp {
                                    let cid = buf[pos + 6 + i * 3];
                                    let sf = buf[pos + 7 + i * 3];
                                    let h = (sf >> 4).max(1);
                                    let v = (sf & 0x0F).max(1);
                                    sof_components.insert(cid, (h, v));
                                }
                            }
                        }
                    }
                    0xC4 => {
                        // DHT — may contain multiple tables packed together.
                        let payload = &buf[pos + 2..pos + seg_len];
                        if parse_dht_segment(payload, &mut tables) {
                            found_dht = true;
                        }
                    }
                    _ => {}
                }

                pos += seg_len;
            }
        }
    }

    if is_progressive || !found_dht || !found_sos || scan_components.is_empty() {
        return None;
    }

    Some(JpegHuffmanContext {
        tables,
        components: scan_components,
    })
}

/// Parse one DHT segment payload (everything after the 2-byte length field).
/// A single DHT segment can contain multiple tables packed end-to-end.
/// Returns `true` if at least one table was successfully parsed.
fn parse_dht_segment(payload: &[u8], tables: &mut [Option<HuffmanTable>; 4]) -> bool {
    let mut pos = 0;
    let mut any_ok = false;
    while pos < payload.len() {
        if pos + 17 > payload.len() {
            break;
        }
        let tc = (payload[pos] >> 4) as usize; // table class: 0=DC, 1=AC
        let th = (payload[pos] & 0x0F) as usize; // table destination id
        pos += 1;

        if tc > 1 || th > 1 {
            break; // invalid table specification for baseline JPEG
        }

        let counts = &payload[pos..pos + 16];
        let total_syms: usize = counts.iter().map(|&c| c as usize).sum();
        pos += 16;

        if pos + total_syms > payload.len() {
            break;
        }

        let dht_payload_slice = &payload[pos - 16..pos + total_syms]; // counts + symbols
        if let Some(tbl) = HuffmanTable::from_dht_payload(dht_payload_slice) {
            let slot = (tc << 1) | th;
            tables[slot] = Some(tbl);
            any_ok = true;
        }

        pos += total_syms;
    }
    any_ok
}

/// Decode JPEG scan data and return the number of MCUs that decoded
/// successfully using the provided Huffman context.
///
/// Decoding stops at the first MCU that fails, at EOI, or at EOF.
/// Returns `0` if decoding fails immediately (wrong tables, corrupt data).
pub fn count_valid_mcus(ctx: &JpegHuffmanContext, scan_data: &[u8]) -> usize {
    let mut reader = BitstreamReader::new(scan_data);
    let mut mcu_count = 0usize;
    // DC prediction state: one value per scan component.
    let mut prev_dc: Vec<i32> = vec![0; ctx.components.len()];

    loop {
        if reader.at_end() {
            break;
        }
        // Check for restart marker — RST0-RST7 sit between MCUs.
        if let Some(marker) = reader.peek_marker() {
            if (0xD0..=0xD7).contains(&marker) {
                reader.skip_marker();
                prev_dc.fill(0);
                continue;
            } else if marker == 0xD9 {
                break; // EOI
            }
            // Unexpected marker inside scan data — treat as end.
            break;
        }

        if decode_mcu(&mut reader, ctx, &mut prev_dc).is_none() {
            break;
        }
        mcu_count += 1;
    }

    mcu_count
}

// ── Bitstream reader ──────────────────────────────────────────────────────────

/// A bit-level reader over JPEG scan data with transparent FF00 byte-stuffing.
struct BitstreamReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Bit buffer (up to 32 bits pending).
    bit_buf: u32,
    /// Number of valid bits in `bit_buf`.
    bits_left: u8,
    /// Whether we have hit EOF or a marker.
    exhausted: bool,
}

impl<'a> BitstreamReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitstreamReader {
            data,
            pos: 0,
            bit_buf: 0,
            bits_left: 0,
            exhausted: false,
        }
    }

    fn at_end(&self) -> bool {
        self.exhausted && self.bits_left == 0
    }

    /// If the next byte in the raw stream is `0xFF` followed by a non-`0x00`
    /// byte, return the second byte (the marker type) without consuming anything.
    fn peek_marker(&self) -> Option<u8> {
        if self.bits_left > 0 {
            return None; // bits still buffered — not at a raw boundary
        }
        let pos = self.pos;
        if pos + 1 < self.data.len() && self.data[pos] == 0xFF && self.data[pos + 1] != 0x00 {
            Some(self.data[pos + 1])
        } else {
            None
        }
    }

    /// Skip past a `0xFF Mx` marker (2 bytes raw).
    fn skip_marker(&mut self) {
        if self.pos + 1 < self.data.len() {
            self.pos += 2;
        }
        self.exhausted = false;
    }

    /// Fill the bit buffer by reading raw bytes, handling FF00 stuffing.
    fn fill_bits(&mut self) {
        while self.bits_left <= 24 && !self.exhausted {
            if self.pos >= self.data.len() {
                self.exhausted = true;
                break;
            }
            let byte = self.data[self.pos];
            if byte == 0xFF {
                if self.pos + 1 >= self.data.len() {
                    self.exhausted = true;
                    break;
                }
                let next = self.data[self.pos + 1];
                if next == 0x00 {
                    // Stuffed FF — emit 0xFF into the bitstream.
                    self.pos += 2;
                    self.bit_buf = (self.bit_buf << 8) | 0xFF;
                    self.bits_left += 8;
                } else {
                    // Any other FF Xx is a marker — stop filling.
                    self.exhausted = true;
                    break;
                }
            } else {
                self.pos += 1;
                self.bit_buf = (self.bit_buf << 8) | (byte as u32);
                self.bits_left += 8;
            }
        }
    }

    /// Read exactly `n` bits (1 ≤ n ≤ 16).  Returns `None` on EOF.
    fn read_bits(&mut self, n: u8) -> Option<u16> {
        debug_assert!((1..=16).contains(&n));
        if self.bits_left < n {
            self.fill_bits();
        }
        if self.bits_left < n {
            return None;
        }
        self.bits_left -= n;
        let val = (self.bit_buf >> self.bits_left) & ((1 << n) - 1);
        self.bit_buf &= (1 << self.bits_left) - 1;
        Some(val as u16)
    }
}

// ── Huffman decode helpers ────────────────────────────────────────────────────

/// Decode one Huffman symbol from the bitstream using the given table.
fn decode_huffman(reader: &mut BitstreamReader, table: &HuffmanTable) -> Option<u8> {
    let mut code = 0u16;
    for len in 1u8..=16u8 {
        let bit = reader.read_bits(1)?;
        code = (code << 1) | bit;
        let l = len as usize;
        if table.max_code[l] >= 0 && code >= table.min_code[l] && code as i32 <= table.max_code[l] {
            let sym_idx = (table.val_ptr[l] + code as i32) as usize;
            if sym_idx < table.symbols.len() {
                return Some(table.symbols[sym_idx]);
            }
            return None;
        }
    }
    None // no valid code found within 16 bits
}

/// Receive (decode additional magnitude bits) for a JPEG coefficient category.
/// Returns the signed coefficient value.
fn receive_and_extend(reader: &mut BitstreamReader, category: u8) -> Option<i32> {
    if category == 0 {
        return Some(0);
    }
    let bits = reader.read_bits(category)? as i32;
    // Sign extend: if the leading bit is 0, value is negative.
    let vt = 1 << (category - 1);
    if bits < vt {
        Some(bits - (2 * vt - 1))
    } else {
        Some(bits)
    }
}

/// Decode one full MCU.  Returns `Some(())` on success, `None` on failure.
fn decode_mcu(
    reader: &mut BitstreamReader,
    ctx: &JpegHuffmanContext,
    prev_dc: &mut [i32],
) -> Option<()> {
    for (comp_idx, comp) in ctx.components.iter().enumerate() {
        // Each component contributes h_samp × v_samp 8×8 blocks per MCU.
        let blocks = (comp.h_samp as usize) * (comp.v_samp as usize);

        for _block_idx in 0..blocks {
            // ── DC coefficient ────────────────────────────────────────────
            let dc_tbl = ctx.tables[comp.dc_table_idx].as_ref()?;
            let dc_category = decode_huffman(reader, dc_tbl)?;
            if dc_category > 11 {
                return None; // impossible category for DC
            }
            let dc_diff = receive_and_extend(reader, dc_category)?;
            prev_dc[comp_idx] += dc_diff;

            // ── AC coefficients (63 total) ────────────────────────────────
            let ac_tbl = ctx.tables[comp.ac_table_idx].as_ref()?;
            let mut ac_count = 0usize;
            while ac_count < 63 {
                let rs = decode_huffman(reader, ac_tbl)?;
                if rs == 0x00 {
                    // EOB — end-of-block, remaining coefficients are zero.
                    break;
                }
                if rs == 0xF0 {
                    // ZRL — 16 zero AC coefficients.
                    ac_count += 16;
                    continue;
                }
                let run = (rs >> 4) as usize;
                let size = rs & 0x0F;
                if size == 0 || size > 10 {
                    return None; // invalid AC category
                }
                receive_and_extend(reader, size)?;
                ac_count += run + 1;
            }
        }
    }
    Some(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FF-byte validity tests ────────────────────────────────────────────────

    #[test]
    fn test_ff_validity_no_ff() {
        let data = [0x12, 0x34, 0x56, 0x78];
        assert!((ff_byte_validity_score(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_ff_validity_all_valid_stuffed() {
        // FF 00 FF 00 — both FFs are stuffed, score = 1.0
        let data = [0xFF, 0x00, 0xFF, 0x00];
        assert!((ff_byte_validity_score(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_ff_validity_all_valid_restart() {
        let data = [0xFF, 0xD0, 0xFF, 0xD5, 0xFF, 0xD9];
        assert!((ff_byte_validity_score(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_ff_validity_all_invalid() {
        // FF E0 — JFIF APP0 marker inside scan data = invalid
        let data = [0xFF, 0xE0, 0xFF, 0xFE];
        assert!(ff_byte_validity_score(&data) < 1e-9);
    }

    #[test]
    fn test_ff_validity_mixed() {
        // 2 FFs: one valid (FF 00), one invalid (FF E0) → 0.5
        let data = [0xFF, 0x00, 0xFF, 0xE0];
        let score = ff_byte_validity_score(&data);
        assert!((score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_ff_validity_empty() {
        assert!((ff_byte_validity_score(&[]) - 1.0).abs() < 1e-9);
    }

    // ── DHT segment parsing tests ─────────────────────────────────────────────

    /// Construct a minimal DHT payload for a DC table with a handful of codes.
    fn minimal_dc_dht_payload() -> Vec<u8> {
        // Table class=0 (DC), destination=0
        let mut payload = vec![0x00u8]; // Tc|Th
        // 16 code-count bytes: 1 code of length 2, 1 of length 3, rest zero.
        let mut counts = [0u8; 16];
        counts[1] = 1; // 1 code of length 2
        counts[2] = 2; // 2 codes of length 3
        payload.extend_from_slice(&counts);
        // Symbols: category 0, 1, 2
        payload.extend_from_slice(&[0x00, 0x01, 0x02]);
        payload
    }

    #[test]
    fn test_parse_dht_segment_basic() {
        let payload = minimal_dc_dht_payload();
        let mut tables: [Option<HuffmanTable>; 4] = [None, None, None, None];
        let ok = parse_dht_segment(&payload, &mut tables);
        assert!(ok, "should parse at least one table");
        assert!(tables[0].is_some(), "DC table 0 should be populated");
    }

    #[test]
    fn test_parse_dht_segment_too_short() {
        let payload = [0x00u8; 3]; // too short for counts
        let mut tables: [Option<HuffmanTable>; 4] = [None, None, None, None];
        let ok = parse_dht_segment(&payload, &mut tables);
        assert!(!ok);
    }

    // ── parse_huffman_context tests ───────────────────────────────────────────

    /// Build the minimal JFIF + DHT + SOF + SOS header needed for context parsing.
    fn build_minimal_header() -> Vec<u8> {
        let mut buf = Vec::new();
        // SOI
        buf.extend_from_slice(&[0xFF, 0xD8]);
        // APP0 (JFIF)
        buf.extend_from_slice(&[0xFF, 0xE0]);
        let app0_body: &[u8] = &[
            b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
        ];
        let app0_len = (app0_body.len() + 2) as u16;
        buf.extend_from_slice(&app0_len.to_be_bytes());
        buf.extend_from_slice(app0_body);

        // DHT for DC table 0
        {
            let mut dht_body: Vec<u8> = vec![0x00]; // Tc=0 Th=0
            let mut counts = [0u8; 16];
            counts[1] = 1;
            counts[2] = 2;
            dht_body.extend_from_slice(&counts);
            dht_body.extend_from_slice(&[0x00, 0x01, 0x02]);
            let dht_len = (dht_body.len() + 2) as u16;
            buf.extend_from_slice(&[0xFF, 0xC4]);
            buf.extend_from_slice(&dht_len.to_be_bytes());
            buf.extend_from_slice(&dht_body);
        }
        // DHT for AC table 0
        {
            let mut dht_body: Vec<u8> = vec![0x10]; // Tc=1 Th=0
            let mut counts = [0u8; 16];
            counts[1] = 1; // just EOB (0x00) at length 2
            counts[2] = 1;
            dht_body.extend_from_slice(&counts);
            dht_body.extend_from_slice(&[0x00, 0x11]); // EOB + one non-zero code
            let dht_len = (dht_body.len() + 2) as u16;
            buf.extend_from_slice(&[0xFF, 0xC4]);
            buf.extend_from_slice(&dht_len.to_be_bytes());
            buf.extend_from_slice(&dht_body);
        }
        // SOF0 (baseline): precision=8, height=8, width=8, 1 component
        {
            let sof_body: &[u8] = &[
                0x08, // precision
                0x00, 0x08, // height = 8
                0x00, 0x08, // width = 8
                0x01, // ncomponents = 1
                0x01, // component id = 1
                0x11, // h_samp=1, v_samp=1
                0x00, // qtable = 0
            ];
            let sof_len = (sof_body.len() + 2) as u16;
            buf.extend_from_slice(&[0xFF, 0xC0]);
            buf.extend_from_slice(&sof_len.to_be_bytes());
            buf.extend_from_slice(sof_body);
        }
        // SOS: 1 component using DC table 0 + AC table 0
        {
            let sos_body: &[u8] = &[
                0x01, // Ns = 1 component
                0x01, 0x00, // comp_id=1, Td=0, Ta=0
                0x00, 0x3F, 0x00, // Ss, Se, Ah/Al
            ];
            let sos_len = (sos_body.len() + 2) as u16;
            buf.extend_from_slice(&[0xFF, 0xDA]);
            buf.extend_from_slice(&sos_len.to_be_bytes());
            buf.extend_from_slice(sos_body);
        }
        buf
    }

    #[test]
    fn test_parse_huffman_context_valid() {
        let header = build_minimal_header();
        let ctx = parse_huffman_context(&header);
        assert!(ctx.is_some(), "should parse a valid context");
        let ctx = ctx.expect("build_minimal_header produces a parseable context");
        assert_eq!(ctx.components.len(), 1);
        assert!(ctx.tables[0].is_some(), "DC table 0 should be present");
        assert!(ctx.tables[2].is_some(), "AC table 0 should be present");
    }

    #[test]
    fn test_parse_huffman_context_no_dht() {
        // Build a header with SOI + APP0 + SOS but no DHT.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        let app0: &[u8] = &[
            b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
        ];
        let len = (app0.len() + 2) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(app0);
        // SOS
        let sos: &[u8] = &[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00];
        buf.extend_from_slice(sos);

        let ctx = parse_huffman_context(&buf);
        assert!(ctx.is_none(), "no DHT should return None");
    }

    #[test]
    fn test_parse_huffman_context_progressive() {
        // Replace SOF0 with SOF2.
        let mut header = build_minimal_header();
        // Find the SOF0 marker (FF C0) and change it to SOF2 (FF C2).
        for i in 0..header.len() - 1 {
            if header[i] == 0xFF && header[i + 1] == 0xC0 {
                header[i + 1] = 0xC2;
                break;
            }
        }
        let ctx = parse_huffman_context(&header);
        assert!(ctx.is_none(), "progressive JPEG should return None");
    }

    // ── BitstreamReader tests ─────────────────────────────────────────────────

    #[test]
    fn test_bitstream_reader_basic() {
        // 0xA0 = 1010_0000
        let data = [0xA0u8];
        let mut r = BitstreamReader::new(&data);
        assert_eq!(r.read_bits(1), Some(1));
        assert_eq!(r.read_bits(1), Some(0));
        assert_eq!(r.read_bits(1), Some(1));
        assert_eq!(r.read_bits(1), Some(0));
    }

    #[test]
    fn test_bitstream_reader_ff00_stuffing() {
        // FF 00 should yield the byte FF (1111_1111) in the bitstream.
        let data = [0xFF, 0x00, 0x80];
        let mut r = BitstreamReader::new(&data);
        // Read the stuffed FF byte (8 bits), should be 0xFF = 255.
        let val = r
            .read_bits(8)
            .expect("FF 00 stuffing yields 8 readable bits");
        assert_eq!(val, 0xFF);
        // Then read the 0x80 byte.
        let val2 = r.read_bits(8).expect("0x80 byte yields 8 readable bits");
        assert_eq!(val2, 0x80);
    }

    #[test]
    fn test_bitstream_reader_marker_stop() {
        // FF D9 (EOI marker) — reader should stop filling and return None.
        let data = [0xFF, 0xD9, 0x00];
        let mut r = BitstreamReader::new(&data);
        // No valid bits before the marker.
        let val = r.read_bits(8);
        assert!(val.is_none(), "should not read bits across a marker");
    }

    // ── count_valid_mcus integration test ────────────────────────────────────

    #[test]
    fn test_count_valid_mcus_empty() {
        let header = build_minimal_header();
        if let Some(ctx) = parse_huffman_context(&header) {
            let count = count_valid_mcus(&ctx, &[]);
            assert_eq!(count, 0);
        }
    }

    // ── receive_and_extend tests ──────────────────────────────────────────────

    #[test]
    fn test_receive_and_extend_category_zero() {
        // Category 0 consumes no bits and always returns Some(0).
        let data: [u8; 0] = [];
        let mut reader = BitstreamReader::new(&data);
        assert_eq!(receive_and_extend(&mut reader, 0), Some(0));
    }

    #[test]
    fn test_receive_and_extend_positive() {
        // Category 3, leading bit = 1 → positive value.
        // bits = 0b110 = 6; vt = 1 << 2 = 4; 6 >= 4 → returns 6.
        let data = [0b1100_0000u8]; // first 3 bits = 110
        let mut reader = BitstreamReader::new(&data);
        assert_eq!(receive_and_extend(&mut reader, 3), Some(6));
    }

    #[test]
    fn test_receive_and_extend_negative() {
        // Category 3, leading bit = 0 → negative value.
        // bits = 0b010 = 2; vt = 1 << 2 = 4; 2 < 4 → returns 2 - (2*4 - 1) = 2 - 7 = -5.
        let data = [0b0100_0000u8]; // first 3 bits = 010
        let mut reader = BitstreamReader::new(&data);
        assert_eq!(receive_and_extend(&mut reader, 3), Some(-5));
    }

    // ── count_valid_mcus marker-handling tests ────────────────────────────────

    #[test]
    fn test_count_valid_mcus_with_eoi_marker() {
        // Two MCUs occupy exactly 1 byte (4 bits each), then EOI at a byte
        // boundary — peek_marker() fires and the loop breaks with count = 2.
        //
        // DC table 0: symbol 0x00 (cat 0) = code 0b00 (2 bits), 0 magnitude bits.
        // AC table 0: symbol 0x00 (EOB)   = code 0b00 (2 bits).
        // One MCU = 4 bits. Two MCUs = 8 bits = 0x00.
        let header = build_minimal_header();
        if let Some(ctx) = parse_huffman_context(&header) {
            let scan_data = [0x00u8, 0xFF, 0xD9]; // 2 MCUs + EOI
            let count = count_valid_mcus(&ctx, &scan_data);
            assert_eq!(count, 2, "should decode 2 MCUs before EOI");
        }
    }

    #[test]
    fn test_count_valid_mcus_with_restart_marker() {
        // RST0 (FF D0) at a byte boundary is detected by peek_marker() when
        // bits_left == 0 and exhausted == false.  The restart resets DC
        // prediction and the loop continues decoding.
        //
        // Scan layout: RST0 immediately at start (bits_left=0, not yet
        // exhausted), then 2 MCUs in byte 0x00, then EOI.
        //
        // RST fires at the top of the loop → skip_marker(), prev_dc reset.
        // Then 2 MCUs from 0x00 decoded.  EOI detected via at_end() (exhausted
        // set when fill_bits hit FF D9) → break.  Total = 2 MCUs.
        let header = build_minimal_header();
        if let Some(ctx) = parse_huffman_context(&header) {
            let scan_data = [0xFF, 0xD0, 0x00u8, 0xFF, 0xD9]; // RST0, 2 MCUs, EOI
            let count = count_valid_mcus(&ctx, &scan_data);
            assert_eq!(count, 2, "should decode 2 MCUs after RST0 reset");
        }
    }
}
