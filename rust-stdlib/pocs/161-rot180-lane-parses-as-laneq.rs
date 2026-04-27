// Bug: rot180_lane parses as Rot180LaneQ, emitting `_rot180_laneq_` instead of `_rot180_lane_`.
// Expected: parser maps "rot180_lane" -> Rot180Lane, formatting `_rot180_lane_<base>`.
// Observed: parser maps "rot180_lane" -> Rot180LaneQ, formatting `_rot180_laneq_<base>`.
// Build/run: rustc 161-rot180-lane-parses-as-laneq.rs -o /tmp/poc161 && /tmp/poc161

use std::str::FromStr;

#[derive(Debug, PartialEq)]
enum SuffixKind {
    Rot180Lane,
    Rot180LaneQ,
}

impl FromStr for SuffixKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rot180_lane" => Ok(SuffixKind::Rot180LaneQ),
            "rot180_laneq" => Ok(SuffixKind::Rot180LaneQ),
            _ => Err(format!("unknown {s}")),
        }
    }
}

fn make_neon_suffix(kind: SuffixKind, prefix_q: &str, prefix_char: char, base_size: u32) -> String {
    match kind {
        SuffixKind::Rot180Lane => format!("{prefix_q}_rot180_lane_{prefix_char}{base_size}"),
        SuffixKind::Rot180LaneQ => format!("{prefix_q}_rot180_laneq_{prefix_char}{base_size}"),
    }
}

fn main() {
    let kind = SuffixKind::from_str("rot180_lane").unwrap();
    let intrinsic = make_neon_suffix(kind, "vcadd", 's', 16);
    let expected = "vcadd_rot180_lane_s16";
    println!("token: rot180_lane");
    println!("expected: {expected}");
    println!("observed: {intrinsic}");
    assert_ne!(intrinsic, expected, "bug not present");
    assert_eq!(intrinsic, "vcadd_rot180_laneq_s16");
    println!("BUG TRIGGERED: emitted laneq instead of lane");
}
