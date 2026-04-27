// Bug: parsing a neon_type wildcard with an unsupported dot modifier panics via
//      SuffixKind::from_str(...).unwrap() instead of returning Err(String).
// Expected: Wildcard::from_str returns Err for invalid suffixes (fallible API contract).
// Observed: unwrap on Err panics with "called `Result::unwrap()` on an `Err` value".
// Build/run: rustc 163-invalid-neon-type-modifier-panics.rs -o /tmp/poc163 && /tmp/poc163

use std::str::FromStr;

#[derive(Debug)]
enum SuffixKind {
    Rot180Lane,
}

impl FromStr for SuffixKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rot180_lane" => Ok(SuffixKind::Rot180Lane),
            _ => Err(format!("unknown suffix {s:?}")),
        }
    }
}

#[derive(Debug)]
enum Wildcard {
    NEONType(Option<u8>, Option<u8>, Option<SuffixKind>),
}

impl FromStr for Wildcard {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, modifier) = match s.split_once('.') {
            Some((h, m)) => (h, Some(m)),
            None => (s, None),
        };
        match (head, None::<u8>, None::<u8>, modifier) {
            ("neon_type", index, tuple, modifier) => {
                if let Some(str_suffix) = modifier {
                    let suffix_kind = SuffixKind::from_str(str_suffix);
                    return Ok(Wildcard::NEONType(index, tuple, Some(suffix_kind.unwrap())));
                } else {
                    Ok(Wildcard::NEONType(index, tuple, None))
                }
            }
            _ => Err("invalid wildcard".into()),
        }
    }
}

fn main() {
    let result = std::panic::catch_unwind(|| Wildcard::from_str("neon_type.bad"));
    match result {
        Ok(_) => panic!("expected a panic, did not panic"),
        Err(_) => println!("BUG TRIGGERED: invalid neon_type modifier panicked instead of Err"),
    }
}
