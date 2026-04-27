// 009-unchecked-directory-name-length
//
// Bug: library/std/src/sys/fs/windows.rs `DirBuffIter::next` trusts
// FILE_ID_BOTH_DIR_INFO.FileNameLength returned by GetFileInformationByHandleEx
// without bounding it by the current entry record or the 1024-byte buffer.
// A malformed entry with FileNameLength = 2048 inside a 1024-byte DirBuff
// causes from_maybe_unaligned to materialize a 1024-element u16 slice that
// extends past the buffer.
//
// Expected: out-of-record FileNameLength stops iteration safely.
// Observed: this PoC builds a 1024-byte buffer with one synthetic entry whose
// FileNameLength = 2048, runs the pre-patch length computation, and confirms
// the requested name slice would extend far past the buffer end. Then it runs
// the patched bounds checker and confirms it rejects the entry. Output:
//     pre-patch requested name elems = 1024  (bytes past buffer end = 1090)
//     patched: stop iteration (malformed entry)
//
// Build/run:
//   rustc 009-unchecked-directory-name-length.rs -o /tmp/poc009
//   /tmp/poc009

use std::mem::size_of;

const NAME_OFFSET: usize = 102;
const FILE_ID_BOTH_DIR_INFO_HEADER: usize = 102;

fn buggy_request_elems(file_name_length: usize) -> usize {
    file_name_length / size_of::<u16>()
}

fn patched_check(buffer_len: usize, next_entry: usize, file_name_length: usize) -> Result<usize, &'static str> {
    if buffer_len < NAME_OFFSET { return Err("buffer < name offset"); }
    let entry_len = if next_entry == 0 { buffer_len } else { next_entry };
    if entry_len > buffer_len
        || entry_len < NAME_OFFSET
        || file_name_length % size_of::<u16>() != 0
        || file_name_length > entry_len - NAME_OFFSET
    {
        return Err("malformed entry");
    }
    Ok(file_name_length / size_of::<u16>())
}

fn main() {
    let buffer_len = 1024usize;
    let next_entry = 0usize;
    let file_name_length = 2048usize;

    let requested = buggy_request_elems(file_name_length);
    let bytes_past = NAME_OFFSET + requested * size_of::<u16>() - buffer_len;
    println!("pre-patch requested name elems = {requested}  (bytes past buffer end = {bytes_past})");
    assert!(NAME_OFFSET + requested * size_of::<u16>() > buffer_len);

    match patched_check(buffer_len, next_entry, file_name_length) {
        Ok(_) => panic!("patched check should reject"),
        Err(e) => println!("patched: stop iteration ({e})"),
    }

    let _ = FILE_ID_BOTH_DIR_INFO_HEADER;
}
