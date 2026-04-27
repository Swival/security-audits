// 008-unchecked-reparse-name-bounds
//
// Bug: library/std/src/sys/fs/windows.rs `File::readlink` reads
// SubstituteNameOffset and SubstituteNameLength from the reparse buffer
// without validating that subst_off + subst_len fits inside PathBuffer or
// the returned reparse data. With a malformed
//   SubstituteNameOffset = 0xfffe (bytes)
//   SubstituteNameLength = 2 (bytes)
// the byte offset (after div-by-2) becomes 32767 UTF-16 elements, far past
// the 16 KiB MAXIMUM_REPARSE_DATA_BUFFER_SIZE.
//
// Expected: malformed reparse buffers are rejected with
// ERROR_INVALID_REPARSE_DATA.
// Observed: this PoC builds the same crafted reparse-data layout used in the
// audit and runs both the pre-patch arithmetic and the patched validator on
// it. Pre-patch unsafely computes a slice pointer at PathBuffer + 32767*2
// bytes; we don't dereference it (which would be UB). The PoC prints:
//     pre-patch subst_off (u16 elems) = 32767
//     pre-patch subst_len (u16 elems) = 1
//     pre-patch end byte from PathBuffer = 65536  (>> 16384 buffer)
//     patched validator: rejected (ERROR_INVALID_REPARSE_DATA)
//
// Build/run:
//   rustc 008-unchecked-reparse-name-bounds.rs -o /tmp/poc008
//   /tmp/poc008

const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16384;
const HEADER_SIZE: usize = 8;
const PATH_BUFFER_OFFSET_IN_SYMLINK: usize = 12;

fn buggy(subst_off_bytes: u16, subst_len_bytes: u16) -> (u16, u16, usize) {
    let subst_off = subst_off_bytes / 2;
    let subst_len = subst_len_bytes / 2;
    let end_bytes = (subst_off as usize) * 2 + (subst_len as usize) * 2;
    (subst_off, subst_len, end_bytes)
}

fn patched(
    bytes_returned: usize,
    reparse_data_len: usize,
    subst_off: u16,
    subst_len: u16,
) -> Result<(), &'static str> {
    if bytes_returned < HEADER_SIZE || bytes_returned > MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
        return Err("invalid reparse data (bytes_returned)");
    }
    if bytes_returned - HEADER_SIZE < reparse_data_len {
        return Err("invalid reparse data (data length)");
    }
    if reparse_data_len < PATH_BUFFER_OFFSET_IN_SYMLINK {
        return Err("invalid reparse data (path buffer)");
    }
    let path_buffer_len = reparse_data_len - PATH_BUFFER_OFFSET_IN_SYMLINK;
    let end = (subst_off as usize)
        .checked_add(subst_len as usize)
        .ok_or("overflow")?;
    if subst_off % 2 != 0 || subst_len % 2 != 0 || end > path_buffer_len {
        return Err("invalid reparse data (offset/length)");
    }
    Ok(())
}

fn main() {
    let subst_off_bytes: u16 = 0xfffe;
    let subst_len_bytes: u16 = 2;
    let bytes_returned: usize = HEADER_SIZE + PATH_BUFFER_OFFSET_IN_SYMLINK + 4;
    let reparse_data_len: usize = PATH_BUFFER_OFFSET_IN_SYMLINK + 4;

    let (off, len, end_bytes) = buggy(subst_off_bytes, subst_len_bytes);
    println!("pre-patch subst_off (u16 elems) = {}", off);
    println!("pre-patch subst_len (u16 elems) = {}", len);
    println!("pre-patch end byte from PathBuffer = {}  (>> {} buffer)", end_bytes, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    assert!(end_bytes > MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

    match patched(bytes_returned, reparse_data_len, subst_off_bytes, subst_len_bytes) {
        Err(e) => println!("patched validator: rejected ({e})"),
        Ok(()) => panic!("patched validator should have rejected"),
    }
}
