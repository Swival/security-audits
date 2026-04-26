;; PoC for finding 004: get_body leaks a spawned body stream on
;; single-reader rejection.
;;
;; In src/component/compute/cache.rs:352, entry.body() creates a body
;; BEFORE the single-reader check at line 357-361. If the check fails,
;; the body is dropped without being registered in session state,
;; leaking any background tasks.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: the second get_body call gets HandleBodyUsed error, but
;; the body stream spawned by the first get_body in that failing path
;; is leaked (not cleaned up).

(module
  (import "fastly_cache" "insert"
    (func $cache_insert (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_cache" "transaction_lookup"
    (func $cache_transaction_lookup (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_cache" "get_body"
    (func $cache_get_body (param i32 i32 i64 i64 i32) (result i32)))
  (import "fastly_http_body" "close"
    (func $body_close (param i32) (result i32)))
  (import "fastly_http_body" "write"
    (func $body_write (param i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Cache key at offset 0
  (data (i32.const 0) "leak-test-key")

  ;; cache_write_options at offset 64
  ;; max_age_ns = 60_000_000_000 (60 seconds) = 0x0D_F847_5800
  (data (i32.const 64) "\00\58\47\f8\0d\00\00\00")
  ;; rest zeroed
  (data (i32.const 72) "\00\00\00\00\00\00\00\00")
  (data (i32.const 80) "\00\00\00\00\00\00\00\00")
  (data (i32.const 88) "\00\00\00\00\00\00\00\00")
  (data (i32.const 96) "\05\00\00\00\00\00\00\00")
  (data (i32.const 104) "\00\00\00\00\00\00\00\00")
  (data (i32.const 112) "\00\00\00\00")

  ;; Some body content
  (data (i32.const 128) "hello")

  ;; Output slots
  ;; insert body: 200, cache handle: 204, first body: 208, second body: 212
  ;; nwritten: 216

  (func (export "_start")
    ;; Insert a cache entry
    (call $cache_insert
      (i32.const 0)    ;; key ptr
      (i32.const 13)   ;; key len
      (i32.const 0x1)  ;; options_mask (max_age only)
      (i32.const 64)   ;; options ptr
      (i32.const 200)  ;; body_handle_out
    )
    drop

    ;; Write body content
    (call $body_write
      (i32.load (i32.const 200))
      (i32.const 128) ;; "hello"
      (i32.const 5)
      (i32.const 0)   ;; back
      (i32.const 216) ;; nwritten
    )
    drop

    ;; Close to finalize
    (call $body_close (i32.load (i32.const 200)))
    drop

    ;; Look up the entry
    (call $cache_transaction_lookup
      (i32.const 0)    ;; key
      (i32.const 13)   ;; key len
      (i32.const 0)    ;; no options
      (i32.const 64)   ;; options ptr
      (i32.const 204)  ;; cache_handle_out
    )
    drop

    ;; First get_body - should succeed
    (call $cache_get_body
      (i32.load (i32.const 204))
      (i32.const 0)    ;; options_mask
      (i64.const 0)    ;; from
      (i64.const 0)    ;; to
      (i32.const 208)  ;; body_handle_out
    )
    drop

    ;; Second get_body - should fail with HandleBodyUsed
    ;; but the internal body stream was already spawned before
    ;; the check, leaking it
    (call $cache_get_body
      (i32.load (i32.const 204))
      (i32.const 0)    ;; options_mask
      (i64.const 0)    ;; from
      (i64.const 0)    ;; to
      (i32.const 212)  ;; body_handle_out
    )
    drop
  )
)
