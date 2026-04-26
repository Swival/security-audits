;; PoC for findings 029 and 032: Shielding API issues
;;
;; 029: Oversized shielding backend persists after length error.
;;   In src/wiggle_abi/shielding.rs, backend_for_shield calls
;;   add_backend() before checking if the backend name fits in
;;   the output buffer. If the check fails, the backend is already
;;   registered but the caller gets an error.
;;
;; 032: Shield backend config is ignored after validation.
;;   Shield backend options and config (cache_key, timeouts) are
;;   validated but never applied to the created Backend.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected for 029: backend_for_shield returns BufferLengthError but
;;   the backend was already added to dynamic_backends.
;; Expected for 032: config options are silently discarded.
;;
;; Required fastly.toml:
;;   [local_server.shielding]
;;   [local_server.shielding.sites]
;;   [local_server.shielding.sites."my-shield"]
;;   url = "http://127.0.0.1:7878"
;;   shield = "my-shield"

(module
  (import "fastly_shielding" "backend_for_shield"
    (func $backend_for_shield (param i32 i32 i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Shield name at offset 0
  (data (i32.const 0) "my-shield")

  ;; Output buffer at offset 100, length only 1 byte (too small)
  ;; This triggers the buffer length error AFTER the backend is already
  ;; registered in dynamic_backends.

  (func (export "_start")
    ;; Call backend_for_shield with a tiny output buffer
    ;; The generated backend name will be longer than 1 byte,
    ;; so this should fail with BufferLengthError -- but the
    ;; backend will already be registered
    (call $backend_for_shield
      (i32.const 0)     ;; shield_name_ptr
      (i32.const 9)     ;; shield_name_len ("my-shield")
      (i32.const 0)     ;; config_mask (no options)
      (i32.const 200)   ;; config_ptr (unused)
      (i32.const 100)   ;; backend_name_out
      (i32.const 1)     ;; backend_name_max_len (too small!)
      (i32.const 300)   ;; nwritten_out
    )
    drop
  )
)
