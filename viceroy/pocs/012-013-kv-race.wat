;; PoC for findings 012 and 013: KV store TOCTOU races
;;
;; 012: Insert preconditions race concurrent writers
;;   In src/object_store.rs:88-183, the insert method releases the lock
;;   between lookup() and the actual write. Two concurrent writers with
;;   KvInsertMode::Add can both pass the "key doesn't exist" check.
;;
;; 013: Append and prepend lose concurrent updates
;;   Same TOCTOU: the read-modify-write for Append/Prepend uses a stale
;;   snapshot, so concurrent appends silently overwrite each other.
;;
;; Trigger: serve this module and send TWO concurrent HTTP requests.
;; Each request inserts to the same key with Add mode. In a correct
;; implementation, only the first should succeed (the second should get
;; PreconditionFailed). With the race, both can succeed.
;;
;; This PoC demonstrates the setup. The race requires concurrent
;; execution which is hard to guarantee in a single module, but
;; sending multiple simultaneous requests exercises the shared
;; ObjectStore state.
;;
;; Required fastly.toml:
;;   [local_server.kv_stores]
;;   [local_server.kv_stores.race-store]

(module
  (import "fastly_kv_store" "open"
    (func $kv_store_open (param i32 i32 i32) (result i32)))
  (import "fastly_kv_store" "insert"
    (func $kv_store_insert (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_kv_store" "insert_wait"
    (func $kv_store_insert_wait (param i32 i32) (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new (param i32) (result i32)))
  (import "fastly_http_body" "write"
    (func $body_write (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_http_resp" "new"
    (func $resp_new (param i32) (result i32)))
  (import "fastly_http_resp" "status_set"
    (func $resp_status_set (param i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $resp_send_downstream (param i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Store name at offset 0
  (data (i32.const 0) "race-store")
  ;; Key at offset 16 - all concurrent requests use the same key
  (data (i32.const 16) "contested-key")
  ;; Body content
  (data (i32.const 32) "my-value")

  ;; kv_insert_config at offset 64
  ;; mode field at offset 0 of struct: Add = 1
  (data (i32.const 64) "\01\00\00\00")

  ;; Output slots: store=200, body=204, insert_handle=208, kv_error=212
  ;; resp=216, resp_body=220, nwritten=224
  ;; status result: 228

  (func (export "_start")
    (local $status i32)

    ;; Open store
    (call $kv_store_open
      (i32.const 0) (i32.const 10) (i32.const 200))
    drop

    ;; Create body with content
    (call $body_new (i32.const 204))
    drop
    (call $body_write
      (i32.load (i32.const 204))
      (i32.const 32) (i32.const 8)
      (i32.const 0) (i32.const 224))
    drop

    ;; Insert with Add mode (should fail if key already exists)
    ;; config_mask: bit for mode = 0x2
    (call $kv_store_insert
      (i32.load (i32.const 200))    ;; store handle
      (i32.const 16) (i32.const 13) ;; key
      (i32.load (i32.const 204))    ;; body handle
      (i32.const 0x2)               ;; config mask (mode)
      (i32.const 64)                ;; config ptr
      (i32.const 208)               ;; insert handle out
    )
    local.set $status

    ;; Wait for insert
    (call $kv_store_insert_wait
      (i32.load (i32.const 208))
      (i32.const 212)  ;; kv_error_out
    )
    drop

    ;; Send response with the insert status
    (call $resp_new (i32.const 216))
    drop
    (call $body_new (i32.const 220))
    drop

    ;; If kv_error == OK (1), the insert succeeded
    ;; With the race, both concurrent requests can succeed
    (if (i32.eq (i32.load (i32.const 212)) (i32.const 1))
      (then
        (call $resp_status_set (i32.load (i32.const 216)) (i32.const 200))
        drop
      )
      (else
        ;; PreconditionFailed or other error
        (call $resp_status_set (i32.load (i32.const 216)) (i32.const 409))
        drop
      )
    )

    (call $resp_send_downstream
      (i32.load (i32.const 216))
      (i32.load (i32.const 220))
      (i32.const 0))
    drop
  )
)
