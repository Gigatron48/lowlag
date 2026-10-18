//! 9-digit connection codes ("482 913 507").

use rand::Rng;

pub const CODE_LEN: usize = 9;

/// A fresh random code. The first digit is never 0 so it always reads as 9 digits.
pub fn generate() -> String {
    let mut rng = rand::rngs::OsRng;
    let mut s = String::with_capacity(CODE_LEN);
    s.push(char::from(b'1' + rng.gen_range(0..9u8)));
    for _ in 1..CODE_LEN {
        s.push(char::from(b'0' + rng.gen_range(0..10u8)));
    }
    s
}

/// Keep only digits; returns `None` unless exactly 9 remain.
pub fn normalize(input: &str) -> Option<String> {
    let d: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
    (d.len() == CODE_LEN).then_some(d)
}

/// "482913507" -> "482 913 507"
pub fn pretty(code: &str) -> String {
    let mut out = String::with_capacity(code.len() + 2);
    for (i, c) in code.chars().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for _ in 0..100 {
            let c = generate();
            assert_eq!(c.len(), 9);
            assert!(!c.starts_with('0'));
            assert_eq!(normalize(&pretty(&c)).as_deref(), Some(c.as_str()));
        }
        assert_eq!(normalize("482-913 507"), Some("482913507".into()));
        assert_eq!(normalize("12345"), None);
        assert_eq!(pretty("482913507"), "482 913 507");
    }
}
