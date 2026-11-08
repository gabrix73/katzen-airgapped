use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

/// Partitioned / grouped optional on-screen keyboard.
///
/// Design principle:
/// Key categories (numbers, letters, symbols) remain partitioned into distinct rows,
/// but are shuffled within each partition to scramble mouse coordinate telemetry.
/// This layout does not establish protection against malware or observation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtualKeyboardState {
    pub numbers: Vec<char>,
    pub letters: Vec<char>,
    pub symbols: Vec<char>,
    pub shift_active: bool,
    pub is_enabled: bool,
    pub used_for_composition: bool,
}

impl Default for VirtualKeyboardState {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualKeyboardState {
    pub fn new() -> Self {
        let mut kbd = Self {
            numbers: vec!['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
            letters: vec![
                'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',
                'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',
                'z', 'x', 'c', 'v', 'b', 'n', 'm',
            ],
            symbols: vec![
                '.', ',', '?', '!', ':', ';', '@', '#', '$', '%',
                '&', '*', '-', '+', '=', '/', '_', '"', '\'', '(',
            ],
            shift_active: false,
            is_enabled: false,
            used_for_composition: false,
        };
        kbd.shuffle_within_groups();
        kbd
    }

    /// Shuffle keys strictly WITHIN each respective group:
    /// - Numbers scramble only among numbers
    /// - Letters scramble only among letters
    /// - Symbols scramble only among symbols
    /// Groups are never mixed together, preserving human ergonomic scanning.
    pub fn shuffle_within_groups(&mut self) {
        let mut rng = rand::thread_rng();
        self.numbers.shuffle(&mut rng);
        self.letters.shuffle(&mut rng);
        self.symbols.shuffle(&mut rng);
    }

    /// Toggle Shift/Caps state
    pub fn toggle_shift(&mut self) {
        self.shift_active = !self.shift_active;
    }

    /// Get current letter character respecting Shift state
    pub fn get_letter_char(&self, c: char) -> char {
        if self.shift_active {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        }
    }

    /// Legacy report fields remain for compatibility; no security score is asserted.
    pub fn compute_secrecy_score(&self) -> SecrecyReport {
        if self.used_for_composition {
            SecrecyReport {
                score_percentage: 0,
                stars: 0,
                shielding_level: "Virtual keyboard enabled".to_string(),
                keylogger_protection: false,
                opsec_note: "Virtual keyboard enabled. This does not protect against compromised software, screen capture, or pointer observation.".to_string(),
            }
        } else {
            SecrecyReport {
                score_percentage: 0,
                stars: 0,
                shielding_level: "Physical keyboard enabled".to_string(),
                keylogger_protection: false,
                opsec_note: "Physical keyboard enabled. Input method alone does not establish an air gap.".to_string(),
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecrecyReport {
    pub score_percentage: u8,
    pub stars: u8,
    pub shielding_level: String,
    pub keylogger_protection: bool,
    pub opsec_note: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grouped_shuffling_preserves_categories() {
        let mut kbd = VirtualKeyboardState::new();
        let mut orig_numbers = kbd.numbers.clone();

        kbd.shuffle_within_groups();

        let mut shuffled = kbd.numbers.clone();
        orig_numbers.sort();
        shuffled.sort();
        assert_eq!(orig_numbers, shuffled);

        // Check that all numbers are still digits
        for c in &kbd.numbers {
            assert!(c.is_ascii_digit(), "Char {} is not a digit", c);
        }
        assert_eq!(kbd.numbers.len(), 10);

        // Check that all letters are lowercase ascii alphabetic
        for c in &kbd.letters {
            assert!(c.is_ascii_alphabetic(), "Char {} is not alphabetic", c);
        }
        assert_eq!(kbd.letters.len(), 26);

        // Check symbols
        for c in &kbd.symbols {
            assert!(!c.is_ascii_alphanumeric(), "Char {} is alphanumeric", c);
        }
        assert_eq!(kbd.symbols.len(), 20);
    }

    #[test]
    fn test_secrecy_score_boost() {
        let mut kbd = VirtualKeyboardState::new();
        let initial_score = kbd.compute_secrecy_score();
        assert_eq!(initial_score.stars, 0);
        assert_eq!(initial_score.score_percentage, 0);
        assert_eq!(initial_score.keylogger_protection, false);

        kbd.used_for_composition = true;
        let boosted_score = kbd.compute_secrecy_score();
        assert_eq!(boosted_score.stars, 0);
        assert_eq!(boosted_score.score_percentage, 0);
        assert_eq!(boosted_score.keylogger_protection, false);
    }
}
