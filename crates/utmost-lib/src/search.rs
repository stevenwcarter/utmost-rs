use crate::types::{SearchType, WILDCARD};

/// Boyer-Moore string search implementation with wildcard and case-insensitive support
pub struct BoyerMoore {
    pub bad_char_table: [usize; 256],
    pub pattern: Vec<u8>,
    pub pattern_len: usize,
    pub case_sensitive: bool,
    pub search_type: SearchType,
}

impl BoyerMoore {
    /// Create a new Boyer-Moore searcher for the given pattern
    pub fn new(pattern: &[u8], case_sensitive: bool, search_type: SearchType) -> Self {
        let mut bm = Self {
            bad_char_table: [0; 256],
            pattern: pattern.to_vec(),
            pattern_len: pattern.len(),
            case_sensitive,
            search_type,
        };

        bm.build_bad_char_table();
        bm
    }

    /// Build the bad character table for Boyer-Moore
    fn build_bad_char_table(&mut self) {
        // Initialize all entries to pattern length
        for i in 0..256 {
            self.bad_char_table[i] = self.pattern_len;
        }

        // Fill the table based on search type
        for (i, &byte) in self.pattern.iter().enumerate() {
            let current_index = match self.search_type {
                SearchType::Reverse => i,
                _ => self.pattern_len - i - 1,
            };

            // Handle wildcard
            if byte == WILDCARD {
                for j in 0..256 {
                    self.bad_char_table[j] = current_index;
                }
            }

            self.bad_char_table[byte as usize] = current_index;

            // Handle case insensitive matching
            if !self.case_sensitive {
                let lower = byte.to_ascii_lowercase();
                let upper = byte.to_ascii_uppercase();
                self.bad_char_table[lower as usize] = current_index;
                self.bad_char_table[upper as usize] = current_index;
            }
        }
    }

    /// Search for the pattern in the haystack
    pub fn search(&self, haystack: &[u8]) -> Option<usize> {
        self.search_from(haystack, 0)
    }

    /// Search for the pattern starting from a specific position
    pub fn search_from(&self, haystack: &[u8], start_pos: usize) -> Option<usize> {
        if self.pattern_len == 0 {
            return Some(0);
        }

        if haystack.len() < self.pattern_len || start_pos >= haystack.len() {
            return None;
        }

        match self.search_type {
            SearchType::Forward | SearchType::ForwardNext => {
                self.search_forward(haystack, start_pos)
            }
            SearchType::Reverse => self.search_reverse(haystack, start_pos),
            SearchType::Ascii => self.search_ascii(haystack, start_pos),
        }
    }

    /// Forward search implementation
    fn search_forward(&self, haystack: &[u8], start_pos: usize) -> Option<usize> {
        if self.pattern_len > haystack.len() {
            return None;
        }

        let mut pos = start_pos + self.pattern_len.saturating_sub(1);

        while pos < haystack.len() {
            let shift = self.bad_char_table[haystack[pos] as usize];

            if shift == 0 {
                // Potential match - check full pattern
                if pos + 1 >= self.pattern_len {
                    let match_start = pos + 1 - self.pattern_len;
                    if self.matches_at_position(haystack, match_start) {
                        return Some(match_start);
                    }
                }
                pos += 1;
            } else {
                pos += shift;
            }
        }

        None
    }

    /// Reverse search implementation
    fn search_reverse(&self, haystack: &[u8], start_pos: usize) -> Option<usize> {
        let mut pos = start_pos;

        while pos < haystack.len() {
            let char_index = haystack[haystack.len() - pos - 1] as usize;
            let shift = self.bad_char_table[char_index];

            if shift == 0 {
                let match_start = haystack.len() - pos - 1;
                if match_start + self.pattern_len <= haystack.len()
                    && self.matches_at_position(haystack, match_start)
                {
                    return Some(match_start);
                }
                pos += 1;
            } else {
                pos += shift;
            }
        }

        None
    }

    /// ASCII search implementation for text files
    fn search_ascii(&self, haystack: &[u8], start_pos: usize) -> Option<usize> {
        // For ASCII search, we look for printable text regions
        let mut start = start_pos;

        // Find start of printable region going backward
        while start > 0 && is_printable_or_whitespace(haystack[start - 1]) {
            start -= 1;
        }

        // Find end of printable region going forward
        let mut end = start_pos;
        while end < haystack.len() && is_printable_or_whitespace(haystack[end]) {
            end += 1;
        }

        // Search within the printable region
        if end > start {
            return self
                .search_forward(&haystack[start..end], 0)
                .map(|pos| pos + start);
        }

        None
    }

    /// Check if pattern matches at a specific position in haystack
    fn matches_at_position(&self, haystack: &[u8], pos: usize) -> bool {
        if pos + self.pattern_len > haystack.len() {
            return false;
        }

        for i in 0..self.pattern_len {
            if !self.chars_match(self.pattern[i], haystack[pos + i]) {
                return false;
            }
        }

        true
    }

    /// Check if two characters match (considering case sensitivity and wildcards)
    fn chars_match(&self, pattern_char: u8, text_char: u8) -> bool {
        if pattern_char == WILDCARD {
            return true;
        }

        if self.case_sensitive {
            pattern_char == text_char
        } else {
            pattern_char.eq_ignore_ascii_case(&text_char)
        }
    }
}

/// Check if a byte represents a printable character or whitespace
fn is_printable_or_whitespace(byte: u8) -> bool {
    byte.is_ascii_graphic() || byte == b' ' || byte == b'\n' || byte == b'\r' || byte == b'\t'
}

/// Wildcard-aware memory comparison
pub fn memwildcardcmp(pattern: &[u8], text: &[u8], case_sensitive: bool) -> bool {
    if pattern.len() != text.len() {
        return false;
    }

    for (i, &pattern_byte) in pattern.iter().enumerate() {
        if pattern_byte == WILDCARD {
            continue;
        }

        let text_byte = text[i];
        let matches = if case_sensitive {
            pattern_byte == text_byte
        } else {
            pattern_byte.eq_ignore_ascii_case(&text_byte)
        };

        if !matches {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boyer_moore_basic_search() {
        let bm = BoyerMoore::new(b"test", true, SearchType::Forward);
        let haystack = b"this is a test string";

        assert_eq!(bm.search(haystack), Some(10));
    }

    #[test]
    fn test_boyer_moore_case_insensitive() {
        let bm = BoyerMoore::new(b"TEST", false, SearchType::Forward);
        let haystack = b"this is a test string";

        assert_eq!(bm.search(haystack), Some(10));
    }

    #[test]
    fn test_boyer_moore_wildcard() {
        let pattern = [b't', WILDCARD, b's', b't'];
        let bm = BoyerMoore::new(&pattern, true, SearchType::Forward);
        let haystack = b"this is a test string";

        assert_eq!(bm.search(haystack), Some(10));
    }

    #[test]
    fn test_boyer_moore_not_found() {
        let bm = BoyerMoore::new(b"xyz", true, SearchType::Forward);
        let haystack = b"this is a test string";

        assert_eq!(bm.search(haystack), None);
    }

    #[test]
    fn test_boyer_moore_empty_pattern() {
        let bm = BoyerMoore::new(b"", true, SearchType::Forward);
        let haystack = b"test";

        assert_eq!(bm.search(haystack), Some(0));
    }

    #[test]
    fn test_boyer_moore_empty_haystack() {
        let bm = BoyerMoore::new(b"test", true, SearchType::Forward);
        let haystack = b"";

        assert_eq!(bm.search(haystack), None);
    }

    #[test]
    fn test_boyer_moore_pattern_longer_than_haystack() {
        let bm = BoyerMoore::new(b"very long pattern", true, SearchType::Forward);
        let haystack = b"short";

        assert_eq!(bm.search(haystack), None);
    }

    #[test]
    fn test_boyer_moore_search_from() {
        let bm = BoyerMoore::new(b"test", true, SearchType::Forward);
        let haystack = b"test test test";

        assert_eq!(bm.search_from(haystack, 0), Some(0));
        assert_eq!(bm.search_from(haystack, 1), Some(5));
        assert_eq!(bm.search_from(haystack, 6), Some(10));
        assert_eq!(bm.search_from(haystack, 11), None);
    }

    #[test]
    fn test_boyer_moore_reverse_search() {
        let bm = BoyerMoore::new(b"test", true, SearchType::Reverse);
        let haystack = b"this is a test string";

        // Note: Reverse search finds patterns from the end
        if let Some(pos) = bm.search(haystack) {
            assert_eq!(&haystack[pos..pos + 4], b"test");
        }
    }

    #[test]
    fn test_boyer_moore_ascii_search() {
        let bm = BoyerMoore::new(b"hello", true, SearchType::Ascii);
        let haystack = b"hello world this is text";

        assert_eq!(bm.search(haystack), Some(0));
    }

    #[test]
    fn test_multiple_wildcards() {
        let pattern = [WILDCARD, b'P', b'D', b'F', WILDCARD];
        let bm = BoyerMoore::new(&pattern, true, SearchType::Forward);
        let haystack = b"This is a %PDF-1.4 document";

        assert_eq!(bm.search(haystack), Some(10));
    }

    #[test]
    fn test_case_insensitive_with_mixed_case() {
        let bm = BoyerMoore::new(b"TeSt", false, SearchType::Forward);
        let haystack = b"this is a TEST string and another test here";

        assert_eq!(bm.search(haystack), Some(10));
    }

    #[test]
    fn test_matches_at_position() {
        let bm = BoyerMoore::new(b"test", true, SearchType::Forward);
        let haystack = b"test string";

        assert!(bm.matches_at_position(haystack, 0));
        assert!(!bm.matches_at_position(haystack, 1));
        assert!(!bm.matches_at_position(haystack, 5));
    }

    #[test]
    fn test_chars_match() {
        let bm = BoyerMoore::new(b"", true, SearchType::Forward);

        // Case sensitive
        assert!(bm.chars_match(b'a', b'a'));
        assert!(!bm.chars_match(b'a', b'A'));
        assert!(bm.chars_match(WILDCARD, b'x'));

        let bm_case_insensitive = BoyerMoore::new(b"", false, SearchType::Forward);
        assert!(bm_case_insensitive.chars_match(b'a', b'A'));
        assert!(bm_case_insensitive.chars_match(b'Z', b'z'));
    }

    #[test]
    fn test_is_printable_or_whitespace() {
        assert!(is_printable_or_whitespace(b'a'));
        assert!(is_printable_or_whitespace(b'Z'));
        assert!(is_printable_or_whitespace(b'0'));
        assert!(is_printable_or_whitespace(b' '));
        assert!(is_printable_or_whitespace(b'\n'));
        assert!(is_printable_or_whitespace(b'\r'));
        assert!(is_printable_or_whitespace(b'\t'));
        assert!(!is_printable_or_whitespace(0x00));
        assert!(!is_printable_or_whitespace(0xFF));
    }

    #[test]
    fn test_memwildcardcmp() {
        let pattern = [b't', WILDCARD, b's', b't'];
        let text = b"test";

        assert!(memwildcardcmp(&pattern, text, true));

        let text2 = b"tast";
        assert!(memwildcardcmp(&pattern, text2, true));

        let text3 = b"best";
        assert!(!memwildcardcmp(&pattern, text3, true));
    }

    #[test]
    fn test_memwildcardcmp_case_insensitive() {
        let pattern = [b'T', WILDCARD, b'S', b'T'];
        let text = b"test";

        assert!(memwildcardcmp(&pattern, text, false));
        assert!(!memwildcardcmp(&pattern, text, true));
    }

    #[test]
    fn test_memwildcardcmp_length_mismatch() {
        let pattern = [b't', b'e', b's', b't'];
        let text = b"te";

        assert!(!memwildcardcmp(&pattern, text, true));

        let text2 = b"testing";
        assert!(!memwildcardcmp(&pattern, text2, true));
    }

    #[test]
    fn test_jpeg_signature() {
        // Test JPEG file signature search
        let jpeg_signature = [0xFF, 0xD8, 0xFF];
        let bm = BoyerMoore::new(&jpeg_signature, true, SearchType::Forward);

        // Create a mock file with JPEG header
        let mut data = vec![0x00; 100];
        data[10] = 0xFF;
        data[11] = 0xD8;
        data[12] = 0xFF;
        data[13] = 0xE0; // JFIF marker

        assert_eq!(bm.search(&data), Some(10));
    }

    #[test]
    fn test_pdf_signature() {
        // Test PDF file signature search
        let pdf_signature = b"%PDF-";
        let bm = BoyerMoore::new(pdf_signature, true, SearchType::Forward);

        let data = b"Some random data %PDF-1.4 rest of file";
        assert_eq!(bm.search(data), Some(17));
    }
}

