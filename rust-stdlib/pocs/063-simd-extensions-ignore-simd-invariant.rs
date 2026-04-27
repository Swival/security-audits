// Bug: aarch64 std_detect parser enabled SIMD extension features (aes, sha2, rdm,
//      dotprod, sve) using only the raw asimd register field, ignoring the full SIMD
//      predicate `fp && asimd && (!fphp | asimdhp)`. Result: extensions reported
//      available while asimd itself is reported unavailable.
// Expected: SIMD extensions gated by the SIMD predicate.
// Observed: pre-patch, register image with fp=false, asimd=true, aes-bits set yields
//           asimd=false but aes=true.
// Build/run: rustc 063-simd-extensions-ignore-simd-invariant.rs -o /tmp/poc063 && /tmp/poc063

fn bits_shift(reg: u64, hi: u32, lo: u32) -> u64 {
    let width = hi - lo + 1;
    let mask = (1u64 << width) - 1;
    (reg >> lo) & mask
}

#[derive(Default, Debug)]
struct Features {
    asimd: bool,
    aes: bool,
    sha2: bool,
    rdm: bool,
    dotprod: bool,
    sve: bool,
}

fn parse_buggy(aa64pfr0: u64, aa64isar0: u64) -> Features {
    let mut f = Features::default();
    let fp = bits_shift(aa64pfr0, 19, 16) < 0xF;
    let fphp = bits_shift(aa64pfr0, 19, 16) >= 1;
    let asimd = bits_shift(aa64pfr0, 23, 20) < 0xF;
    let asimdhp = bits_shift(aa64pfr0, 23, 20) >= 1;
    f.asimd = fp && asimd && (!fphp | asimdhp);
    f.aes = asimd && bits_shift(aa64isar0, 7, 4) >= 2;
    let sha1 = bits_shift(aa64isar0, 11, 8) >= 1;
    let sha2 = bits_shift(aa64isar0, 15, 12) >= 1;
    f.sha2 = asimd && sha1 && sha2;
    f.rdm = asimd && bits_shift(aa64isar0, 31, 28) >= 1;
    f.dotprod = asimd && bits_shift(aa64isar0, 47, 44) >= 1;
    f.sve = asimd && bits_shift(aa64pfr0, 35, 32) >= 1;
    f
}

fn main() {
    let mut aa64pfr0 = 0u64;
    aa64pfr0 |= 0xF << 16;
    aa64pfr0 |= 0x1 << 20;
    aa64pfr0 |= 0x1 << 32;

    let mut aa64isar0 = 0u64;
    aa64isar0 |= 0x2 << 4;
    aa64isar0 |= 0x1 << 8;
    aa64isar0 |= 0x1 << 12;
    aa64isar0 |= 0x1 << 28;
    aa64isar0 |= 0x1 << 44;

    let f = parse_buggy(aa64pfr0, aa64isar0);
    assert!(!f.asimd, "asimd should be off because fp is off");
    assert!(f.aes && f.sha2 && f.rdm && f.dotprod && f.sve,
        "extensions reported on despite asimd off: {:?}", f);
    println!("triggered: asimd={} aes={} sha2={} rdm={} dotprod={} sve={}",
        f.asimd, f.aes, f.sha2, f.rdm, f.dotprod, f.sve);
}
