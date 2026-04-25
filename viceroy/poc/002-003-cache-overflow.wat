;; PoC for findings 002 and 003: Cache duration/age overflow panics
;;
;; 002: get_max_age_ns panics when Duration::as_nanos() exceeds u64::MAX
;;   In src/component/compute/cache.rs:559 and wiggle_abi/cache.rs:642
;;
;; 003: get_age_ns panics when Duration::as_nanos() exceeds u64::MAX
;;   In src/component/compute/cache.rs:581 and wiggle_abi/cache.rs:663
;;
;; The cache insert API accepts max_age_ns and initial_age_ns as u64.
;; Internally these become Duration values. When read back via
;; get_max_age_ns/get_age_ns, Duration::as_nanos() returns u128 which
;; is then try_into::<u64>().unwrap(). If the value exceeds u64::MAX
;; nanos (~584 years), the unwrap panics.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: host panic on the try_into().unwrap() overflow.
;;
;; Note: the cache_write_options struct layout must match the WITX
;; definition. The struct has: max_age_ns(u64), initial_age_ns(u64), ...

(module
  (import "fastly_cache" "insert"
    (func $cache_insert (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_cache" "transaction_lookup"
    (func $cache_transaction_lookup (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_cache" "get_max_age_ns"
    (func $cache_get_max_age_ns (param i32 i32) (result i32)))
  (import "fastly_cache" "get_age_ns"
    (func $cache_get_age_ns (param i32 i32) (result i32)))
  (import "fastly_cache" "get_state"
    (func $cache_get_state (param i32 i32) (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new (param i32) (result i32)))
  (import "fastly_http_body" "close"
    (func $body_close (param i32) (result i32)))

  (memory (export "memory") 1)

  ;; Cache key "overflow-test" at offset 0
  (data (i32.const 0) "overflow-test")

  ;; cache_write_options struct at offset 64:
  ;;   max_age_ns: u64 (8 bytes) at +0  = offset 64
  ;;   initial_age_ns: u64 (8 bytes) at +8 = offset 72
  ;;   stale_while_revalidate_ns: u64 (8 bytes) at +16 = offset 80
  ;;   surrogate_keys_ptr: u32 (4 bytes) at +24 = offset 88
  ;;   surrogate_keys_len: u32 (4 bytes) at +28 = offset 92
  ;;   length: u64 (8 bytes) at +32 = offset 96
  ;;   user_metadata_ptr: u32 at +40 = offset 104
  ;;   user_metadata_len: u32 at +44 = offset 108
  ;;   sensitive_data: u32 at +48 = offset 112
  ;;
  ;; Set max_age_ns to u64::MAX = 0xFFFFFFFF_FFFFFFFF
  (data (i32.const 64) "\ff\ff\ff\ff\ff\ff\ff\ff")
  ;; Set initial_age_ns to u64::MAX
  (data (i32.const 72) "\ff\ff\ff\ff\ff\ff\ff\ff")
  ;; stale_while_revalidate_ns = 0
  (data (i32.const 80) "\00\00\00\00\00\00\00\00")
  ;; surrogate_keys = null, length 0
  (data (i32.const 88) "\00\00\00\00\00\00\00\00")
  ;; length = 0
  (data (i32.const 96) "\00\00\00\00\00\00\00\00")
  ;; user_metadata = null, length 0
  (data (i32.const 104) "\00\00\00\00\00\00\00\00")
  ;; sensitive_data = 0
  (data (i32.const 112) "\00\00\00\00")

  ;; Output slots
  ;; body_handle: offset 200
  ;; cache_handle: offset 204
  ;; state: offset 208
  ;; duration_out: offset 216 (u64)

  (func (export "_start")
    ;; Insert into cache with max_age_ns = u64::MAX
    ;; options_mask: bit 0 = max_age (always required)
    ;;              bit 2 = initial_age
    ;; 0x5 = max_age | initial_age
    (call $cache_insert
      (i32.const 0)    ;; cache key ptr
      (i32.const 13)   ;; cache key len
      (i32.const 0x5)  ;; options_mask: max_age + initial_age
      (i32.const 64)   ;; options ptr
      (i32.const 200)  ;; body_handle_out
    )
    drop

    ;; Close the body to complete the insert
    (call $body_close (i32.load (i32.const 200)))
    drop

    ;; Look up the entry we just inserted
    (call $cache_transaction_lookup
      (i32.const 0)    ;; cache key ptr
      (i32.const 13)   ;; cache key len
      (i32.const 0)    ;; options_mask (none)
      (i32.const 64)   ;; options ptr (unused)
      (i32.const 204)  ;; cache_handle_out
    )
    drop

    ;; Try to read back max_age_ns -- this should panic
    ;; because Duration::as_nanos() returns u128 > u64::MAX
    (call $cache_get_max_age_ns
      (i32.load (i32.const 204))  ;; cache handle
      (i32.const 216)             ;; duration_out
    )
    drop
  )
)
