// Bug: Ord on InputType::NVariantOp(Some(_)) compares all Some(_) as Equal, violating
//      Eq/Ord consistency.
// Expected: Ord must agree with derived Eq: distinct WildString operands compare as
//           Less or Greater, never Equal.
// Observed: Distinct operands op2 vs op3 compare as Equal under Ord, but Eq says they
//           are not equal. A BTreeSet collapses them to a single key.
// Build/run: rustc 162-ord-inconsistent-with-eq-for-nvariantop.rs -o /tmp/poc162 && /tmp/poc162

use std::cmp::Ordering;
use std::collections::BTreeSet;

type WildString = String;

#[derive(Debug, PartialEq, Eq, Clone)]
enum InputType {
    NVariantOp(Option<WildString>),
}

impl PartialOrd for InputType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InputType {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (InputType::NVariantOp(None), InputType::NVariantOp(Some(..))) => Ordering::Less,
            (InputType::NVariantOp(Some(..)), InputType::NVariantOp(None)) => Ordering::Greater,
            (InputType::NVariantOp(_), InputType::NVariantOp(_)) => Ordering::Equal,
        }
    }
}

fn main() {
    let a = InputType::NVariantOp(Some("op2".into()));
    let b = InputType::NVariantOp(Some("op3".into()));

    let eq = a == b;
    let ord = a.cmp(&b);
    println!("a == b: {eq}");
    println!("a.cmp(&b): {:?}", ord);
    assert!(!eq);
    assert_eq!(ord, Ordering::Equal);

    let mut set: BTreeSet<InputType> = BTreeSet::new();
    set.insert(a.clone());
    set.insert(b.clone());
    println!("BTreeSet len after inserting a, b: {}", set.len());
    assert_eq!(set.len(), 1, "ord-inconsistent-with-eq collapses keys");
    println!("BUG TRIGGERED: Ord disagrees with Eq, BTreeSet drops the second value");
}
