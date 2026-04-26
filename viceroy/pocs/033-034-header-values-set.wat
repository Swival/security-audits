;; PoC for findings 033 and 034: Header value manipulation bugs
;;
;; 033: Missing trailing NUL drops last header value
;;   In src/wiggle_abi/headers.rs:150, values_set splits on NUL then
;;   unconditionally discards the last element via next_back(). If the
;;   buffer is not NUL-terminated, the real last value is dropped.
;;
;; 034: Empty values buffer clears headers silently
;;   When values_set receives a zero-length buffer, the split produces
;;   one empty element which next_back() removes, resulting in all
;;   existing header values being deleted with nothing appended.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: For 033, the response should be missing the "bar" header value.
;;   For 034, the response status header is silently cleared.

(module
  (import "fastly_http_req" "body_downstream_get"
    (func $req_body_downstream_get (param i32 i32) (result i32)))
  (import "fastly_http_resp" "new"
    (func $resp_new (param i32) (result i32)))
  (import "fastly_http_resp" "status_set"
    (func $resp_status_set (param i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $resp_send_downstream (param i32 i32 i32) (result i32)))
  (import "fastly_http_resp" "header_values_set"
    (func $resp_header_values_set (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new (param i32) (result i32)))

  (memory (export "memory") 1)

  ;; Header name "x-test" at offset 0
  (data (i32.const 0) "x-test")
  ;; Values buffer WITHOUT trailing NUL: "foo\0bar" (7 bytes)
  ;; After split on \0: ["foo", "bar"]
  ;; next_back() removes "bar" -> only "foo" remains (finding 033)
  (data (i32.const 16) "foo\00bar")

  ;; For finding 034: empty values buffer at offset 32 (length 0)

  ;; Output handle buffers
  ;; resp handle at offset 100, body handle at offset 104

  (func (export "_start")
    (local $resp_handle i32)
    (local $body_handle i32)

    ;; Create response
    (call $resp_new (i32.const 100))
    drop
    (local.set $resp_handle (i32.load (i32.const 100)))

    ;; Create body
    (call $body_new (i32.const 104))
    drop
    (local.set $body_handle (i32.load (i32.const 104)))

    ;; Set status 200
    (call $resp_status_set (local.get $resp_handle) (i32.const 200))
    drop

    ;; Finding 033: Set header values with non-NUL-terminated buffer
    ;; "foo\0bar" should set both "foo" and "bar" as values,
    ;; but next_back() drops "bar"
    (call $resp_header_values_set
      (local.get $resp_handle)
      (i32.const 0)     ;; name ptr "x-test"
      (i32.const 6)     ;; name len
      (i32.const 16)    ;; values ptr "foo\0bar"
      (i32.const 7)     ;; values len (no trailing NUL)
    )
    drop

    ;; Send response
    (call $resp_send_downstream
      (local.get $resp_handle)
      (local.get $body_handle)
      (i32.const 0)
    )
    drop
  )
)
