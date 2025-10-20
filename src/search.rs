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
            SearchType::Reverse => {
                self.search_reverse(haystack, start_pos)
            }
            SearchType::Ascii => {
                self.search_ascii(haystack, start_pos)
            }
        }
    }

    /// Forward search implementation
    fn search_forward(&self, haystack: &[u8], start_pos: usize) -> Option<usize> {
        let mut pos = start_pos + self.pattern_len - 1;

        while pos < haystack.len() {
            let shift = self.bad_char_table[haystack[pos] as usize];
            
            if shift == 0 {
                // Potential match - check full pattern
                let match_start = pos - self.pattern_len + 1;
                if self.matches_at_position(haystack, match_start) {
                    return Some(match_start);
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
                if match_start + self.pattern_len <= haystack.len() && 
                   self.matches_at_position(haystack, match_start) {
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
            return self.search_forward(&haystack[start..end], 0).map(|pos| pos + start);
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
            pattern_char.to_ascii_lowercase() == text_char.to_ascii_lowercase()
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
            pattern_byte.to_ascii_lowercase() == text_byte.to_ascii_lowercase()
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
    fn test_memwildcardcmp() {
        let pattern = [b't', WILDCARD, b's', b't'];
        let text = b"test";
        
        assert!(memwildcardcmp(&pattern, text, true));
        
        let text2 = b"tast";
        assert!(memwildcardcmp(&pattern, text2, true));
        
        let text3 = b"best";
        assert!(!memwildcardcmp(&pattern, text3, true));
    }
}