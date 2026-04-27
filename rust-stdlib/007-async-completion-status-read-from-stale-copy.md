# async completion status read from stale copy

## Classification

Logic error, medium severity, certain confidence.

## Affected Locations

`library/std/src/sys/net/connection/uefi/tcp4.rs:109`

## Summary

`Tcp4::accept` submits `listen_token.completion_token` to UEFI firmware, waits for that submitted token to complete, but then checks the status on the original local `completion_token` copy. If firmware completes the asynchronous accept with an error status, that error is written into `listen_token.completion_token.status` and is ignored. The function can then proceed as if accept succeeded and attempt to construct a child TCP socket from `listen_token.new_child_handle`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Firmware completes a TCP4 accept request with an error status after the initial `EFI_TCP4_PROTOCOL.Accept()` call succeeds.

## Proof

`accept` initializes:

```rust
let completion_token =
    tcp4::CompletionToken { event: evt.as_ptr(), status: Status::SUCCESS };
let mut listen_token =
    tcp4::ListenToken { completion_token, new_child_handle: ptr::null_mut() };
```

The submitted object is `&mut listen_token`:

```rust
let r = unsafe { ((*protocol).accept)(protocol, &mut listen_token) };
```

The wait also observes the submitted nested token:

```rust
unsafe { self.wait_or_cancel(None, &mut listen_token.completion_token) }?;
```

Before the patch, completion status was read from the stale unsubmitted copy:

```rust
if completion_token.status.is_error() {
    Err(io::Error::from_raw_os_error(completion_token.status.as_usize()))
}
```

Firmware writes asynchronous completion status to `listen_token.completion_token.status`, not to the original copied `completion_token`. Therefore an error completion can be missed and the success branch can run:

```rust
let handle = NonNull::new(listen_token.new_child_handle).unwrap();
let protocol = helpers::open_protocol(handle, tcp4::PROTOCOL_GUID)?;
```

On failed completion, `new_child_handle` is not a valid accepted child handle. If null, this panics through `unwrap()`; if stale or non-null-invalid, the code may open or later destroy the wrong handle path.

## Why This Is A Real Bug

The code passes `&mut listen_token` to firmware and waits on `&mut listen_token.completion_token`, establishing that `listen_token.completion_token` is the authoritative completion token. Checking the separate `completion_token` local after the wait reads a stale copy that remains `Status::SUCCESS`. This directly contradicts the asynchronous completion contract and causes failed accepts to be treated as successful.

## Fix Requirement

After `wait_or_cancel`, check `listen_token.completion_token.status`, not the original `completion_token.status`.

## Patch Rationale

The patch changes only the post-completion status source. It preserves the existing control flow, timeout/cancel behavior, and child-handle construction path, while ensuring the status read comes from the same token submitted to and completed by firmware.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/uefi/tcp4.rs b/library/std/src/sys/net/connection/uefi/tcp4.rs
index ac38dd901e4..289a5ec4a9b 100644
--- a/library/std/src/sys/net/connection/uefi/tcp4.rs
+++ b/library/std/src/sys/net/connection/uefi/tcp4.rs
@@ -104,8 +104,8 @@ pub(crate) fn accept(&self) -> io::Result<Self> {
 
         unsafe { self.wait_or_cancel(None, &mut listen_token.completion_token) }?;
 
-        if completion_token.status.is_error() {
-            Err(io::Error::from_raw_os_error(completion_token.status.as_usize()))
+        if listen_token.completion_token.status.is_error() {
+            Err(io::Error::from_raw_os_error(listen_token.completion_token.status.as_usize()))
         } else {
             // EDK2 internals seem to assume a single ServiceBinding Protocol for TCP4 and TCP6, and
             // thus does not use any service binding protocol data in destroying child sockets. It
```