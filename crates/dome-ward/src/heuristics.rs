//! Heuristic analysis functions for detecting suspicious content.
//!
//! These complement the regex-based pattern scanner with statistical
//! and structural checks that are harder to evade.

/// Calculate the Shannon entropy of a string.
///
/// High entropy (>4.5 for ASCII text) may indicate encoded/encrypted payloads,
/// binary data, or obfuscated content being smuggled through tool arguments.
pub fn entropy_score(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    let len = text.len() as f64;

    for byte in text.bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check if a string looks like base64-encoded data.
///
/// Uses structural heuristics rather than trying to decode, since
/// we want to flag suspicious patterns even if they're not valid base64.
pub fn is_base64_encoded(text: &str) -> bool {
    let trimmed = text.trim();

    // Must be at least 20 chars to reduce false positives
    if trimmed.len() < 20 {
        return false;
    }

    // Base64 chars: A-Z, a-z, 0-9, +, /, =
    let base64_chars = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    let ratio = base64_chars as f64 / trimmed.len() as f64;

    // High ratio of base64 chars + high entropy suggests encoding
    ratio > 0.95 && entropy_score(trimmed) > 4.0
}

/// Check if a string value is suspiciously long for a tool argument.
///
/// Very long strings may indicate payload stuffing, prompt injection
/// hidden in large blocks of text, or data exfiltration via arguments.
pub fn is_suspiciously_long(text: &str, threshold: usize) -> bool {
    text.len() > threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(entropy_score(""), 0.0);
    }

    #[test]
    fn entropy_of_single_char_is_zero() {
        assert_eq!(entropy_score("aaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_normal_english_text() {
        let text = "The quick brown fox jumps over the lazy dog";
        let e = entropy_score(text);
        assert!(e > 3.0 && e < 5.0, "entropy was {e}");
    }

    #[test]
    fn entropy_of_random_looking_data() {
        let text = "aK9xQ2mLpR4nW7jB5vF8eY3hU6iT1oS0dG";
        let e = entropy_score(text);
        assert!(
            e > 4.0,
            "entropy was {e}, expected > 4.0 for random-looking data"
        );
    }

    #[test]
    fn base64_detection_positive() {
        let encoded = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmc=";
        assert!(is_base64_encoded(encoded));
    }

    #[test]
    fn base64_detection_negative_for_normal_text() {
        assert!(!is_base64_encoded("Hello, this is normal text."));
    }

    #[test]
    fn base64_detection_negative_for_short_strings() {
        assert!(!is_base64_encoded("SGVsbG8="));
    }

    #[test]
    fn suspiciously_long_detects_threshold() {
        assert!(!is_suspiciously_long("short", 100));
        assert!(is_suspiciously_long(&"x".repeat(101), 100));
    }
}
