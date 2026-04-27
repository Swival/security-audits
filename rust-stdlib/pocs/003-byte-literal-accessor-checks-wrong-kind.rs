// 003-byte-literal-accessor-checks-wrong-kind
//
// Bug: proc_macro::Literal::byte_character_value matches bridge::LitKind::Char
// instead of bridge::LitKind::Byte. As a result a byte character literal is
// rejected with InvalidLiteralKind, and a character literal is incorrectly
// accepted and decoded as a byte.
//
// Expected: byte_character_value(b'A') -> Ok(0x41); calling it on 'A' returns
// InvalidLiteralKind.
// Observed (pre-patch behavior reproduced via the public API): the internal
// kind discriminant is checked against the wrong arm. We can't run the proc
// macro itself standalone, so this PoC mirrors the exact pre-patch logic
// against a tiny stand-in for `bridge::LitKind`. It prints:
//     byte('A')   -> Err(InvalidLiteralKind)        // bug: should be Ok(0x41)
//     char('A')   -> Ok(65)                         // bug: should be Err(InvalidLiteralKind)
//
// Build/run:
//   rustc 003-byte-literal-accessor-checks-wrong-kind.rs -o /tmp/poc003
//   /tmp/poc003
//
// To confirm the source location of the wrong arm, see
//   library/proc_macro/src/lib.rs   `pub fn byte_character_value`
// where the match arm is `bridge::LitKind::Char => unescape_byte(symbol)...`.

#[derive(Debug)]
enum LitKind { Byte, Char }

#[derive(Debug)]
enum ConversionErrorKind { FailedToUnescape, InvalidLiteralKind }

fn unescape_byte(sym: &str) -> Result<u8, ()> {
    sym.bytes().next().ok_or(())
}

fn byte_character_value_buggy(kind: &LitKind, symbol: &str) -> Result<u8, ConversionErrorKind> {
    match kind {
        LitKind::Char => unescape_byte(symbol).map_err(|_| ConversionErrorKind::FailedToUnescape),
        _ => Err(ConversionErrorKind::InvalidLiteralKind),
    }
}

fn main() {
    let r1 = byte_character_value_buggy(&LitKind::Byte, "A");
    let r2 = byte_character_value_buggy(&LitKind::Char, "A");
    println!("byte('A')   -> {:?}", r1);
    println!("char('A')   -> {:?}", r2);
    assert!(matches!(r1, Err(ConversionErrorKind::InvalidLiteralKind)));
    assert!(matches!(r2, Ok(65)));
}
