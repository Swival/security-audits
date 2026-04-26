;; PoC for finding 011: lookup_wait exposes partial state on buffer error
;;
;; In src/wiggle_abi/kv_store_impl.rs:83-108, the Ok(Some(value)) branch
;; of lookup_wait writes body_handle_out and nwritten_out BEFORE checking
;; if metadata fits in the caller's buffer. If metadata is too large,
;; BufferLengthError is returned but the body handle was already written
;; and inserted into session state.
;;
;; Trigger: serve this module with a KV store containing an entry with
;; metadata longer than the provided buffer.
;;
;; Required fastly.toml:
;;   [local_server.kv_stores.test-store]
;;   key = {data = "value", metadata = "long-metadata-string-that-exceeds-buffer"}

(module
  (import "fastly_kv_store" "open"
    (func $kv_store_open (param i32 i32 i32) (result i32)))
  (import "fastly_kv_store" "lookup"
    (func $kv_store_lookup (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_kv_store" "lookup_wait"
    (func $kv_store_lookup_wait (param i32 i32 i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Store name "test-store" at offset 0
  (data (i32.const 0) "test-store")
  ;; Key name at offset 16
  (data (i32.const 16) "key")

  ;; Output slots
  ;; store handle: 100
  ;; lookup handle: 104
  ;; body handle: 108
  ;; nwritten: 112
  ;; generation: 116
  ;; kv_error: 120
  ;; metadata buffer: 200 (only 4 bytes - intentionally small)

  (func (export "_start")
    ;; Open the KV store
    (call $kv_store_open
      (i32.const 0)    ;; name ptr
      (i32.const 10)   ;; name len
      (i32.const 100)  ;; handle out
    )
    drop

    ;; Lookup a key
    (call $kv_store_lookup
      (i32.load (i32.const 100))  ;; store handle
      (i32.const 16)              ;; key ptr
      (i32.const 3)               ;; key len
      (i32.const 0)               ;; config mask
      (i32.const 300)             ;; config ptr
      (i32.const 104)             ;; lookup handle out
    )
    drop

    ;; Wait for lookup with a tiny metadata buffer (4 bytes)
    ;; If the entry has metadata longer than 4 bytes, this
    ;; should fail with BufferLengthError - but body_handle_out
    ;; at offset 108 will already have been written
    (call $kv_store_lookup_wait
      (i32.load (i32.const 104))  ;; lookup handle
      (i32.const 108)             ;; body_handle_out (gets written first!)
      (i32.const 200)             ;; metadata_buf (only 4 bytes)
      (i32.const 4)               ;; metadata_buf_len (too small)
      (i32.const 112)             ;; nwritten_out (also written early)
      (i32.const 116)             ;; generation_out
      (i32.const 120)             ;; kv_error_out
    )
    drop
    ;; At this point, even though the call may have returned an error,
    ;; offset 108 contains a valid body handle that was leaked
  )
)
