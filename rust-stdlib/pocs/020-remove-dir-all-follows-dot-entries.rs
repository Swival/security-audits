// Bug: SOLID remove_dir_all does not skip "." or ".." entries returned by SOLID_FS_ReadDir,
//      causing recursion into the same/parent directory and possibly deletion outside the tree.
// Expected: dot entries are filtered before child.file_type()/recurse/unlink.
// Observed: this PoC simulates the SOLID readdir loop body; with mocked entries containing
//           "." and "..", remove_dir_all would recurse into them.
// Build/run:
//   rustc /Users/j/src/swival-audits/rust-stdlib/pocs/020-remove-dir-all-follows-dot-entries.rs \
//     -o /tmp/poc020 && /tmp/poc020
// Cross-build check:
//   rustc --target=armv7a-kmc-solid_asp3 --emit=metadata --edition=2021 ... (toolchain dependent)

use std::path::{Path, PathBuf};

struct DirEntry {
    name: Vec<u8>,
    is_dir: bool,
}

impl DirEntry {
    fn file_name(&self) -> &[u8] {
        &self.name
    }
    fn path(&self, root: &Path) -> PathBuf {
        let s = std::str::from_utf8(&self.name).unwrap();
        root.join(s)
    }
}

fn buggy_remove_dir_all(path: &Path, depth: u32, log: &mut Vec<PathBuf>) {
    if depth > 4 {
        log.push(PathBuf::from("STACK-EXHAUSTED"));
        return;
    }
    let entries = mock_readdir(path);
    for child in entries {
        if child.is_dir {
            let child_path = child.path(path);
            log.push(child_path.clone());
            buggy_remove_dir_all(&child_path, depth + 1, log);
        }
    }
}

fn fixed_remove_dir_all(path: &Path, depth: u32, log: &mut Vec<PathBuf>) {
    if depth > 4 {
        log.push(PathBuf::from("STACK-EXHAUSTED"));
        return;
    }
    let entries = mock_readdir(path);
    for child in entries {
        if matches!(child.file_name(), b"." | b"..") {
            continue;
        }
        if child.is_dir {
            let child_path = child.path(path);
            log.push(child_path.clone());
            fixed_remove_dir_all(&child_path, depth + 1, log);
        }
    }
}

fn mock_readdir(_p: &Path) -> Vec<DirEntry> {
    vec![
        DirEntry { name: b".".to_vec(), is_dir: true },
        DirEntry { name: b"..".to_vec(), is_dir: true },
    ]
}

fn main() {
    let root = PathBuf::from(r"C:\target");
    let mut buggy_log = Vec::new();
    buggy_remove_dir_all(&root, 0, &mut buggy_log);
    println!("buggy traversal length: {}", buggy_log.len());
    for p in &buggy_log {
        println!("  visit: {}", p.display());
    }
    assert!(buggy_log.iter().any(|p| p.to_string_lossy().contains("..")),
        "expected buggy version to recurse into ..");
    assert!(buggy_log.iter().any(|p| p.to_string_lossy().contains("STACK-EXHAUSTED")),
        "expected buggy version to recurse unboundedly");

    let mut fixed_log = Vec::new();
    fixed_remove_dir_all(&root, 0, &mut fixed_log);
    println!("fixed traversal length: {}", fixed_log.len());
    assert_eq!(fixed_log.len(), 0, "fixed version skips dot entries");

    println!("BUG TRIGGERED: dot entries cause escape/unbounded recursion in unfixed code");
}
