// Bug: quicksort doc said scratch.len() >= max(v.len() - v.len()/2, SMALL_SORT_GENERAL_SCRATCH_LEN),
// but stable_partition aborts unless scratch.len() >= v.len(). A caller meeting the documented
// contract can hit the abort.
// Expected: documented contract should match implementation requirement (>= v.len()).
// Observed: documented-contract-compliant scratch (48) is rejected by stable_partition for v.len()=49.
// Build/run: rustc 100-incorrect-scratch-length-contract.rs -o /tmp/poc100 && /tmp/poc100

fn documented_min_scratch(v_len: usize, small_sort_scratch: usize) -> usize {
    core::cmp::max(v_len - v_len / 2, small_sort_scratch)
}

fn actual_required_scratch(v_len: usize) -> usize {
    v_len
}

fn stable_partition_aborts(v_len: usize, scratch_len: usize, pivot_pos: usize) -> bool {
    scratch_len < v_len || pivot_pos >= v_len
}

fn main() {
    const SMALL_SORT_GENERAL_SCRATCH_LEN: usize = 48;
    let v_len = 49;
    let documented = documented_min_scratch(v_len, SMALL_SORT_GENERAL_SCRATCH_LEN);
    let required = actual_required_scratch(v_len);
    println!("v.len() = {}", v_len);
    println!("documented min scratch = {}", documented);
    println!("actual required scratch = {}", required);
    let aborts = stable_partition_aborts(v_len, documented, 10);
    println!("stable_partition with documented-min scratch aborts: {}", aborts);
    assert_eq!(documented, 48);
    assert_eq!(required, 49);
    assert!(aborts, "BUG: contract-compliant caller is aborted by stable_partition");
}
