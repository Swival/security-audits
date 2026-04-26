;; PoC for findings 005 and 006: Gzip decoder issues
;;
;; 005: Gzip decoder emits spurious empty terminal chunk
;;   In src/body.rs:310-316, when the inner stream ends, try_finish()
;;   unconditionally returns Some(Ok(chunk)) even when the chunk is empty.
;;
;; 006: Full body read has no decompressed size limit
;;   In src/body.rs:149-157, read_into_vec accumulates decompressed
;;   data without any size cap. A gzip bomb could exhaust host memory.
;;
;; Trigger: configure a backend that returns gzip-compressed responses.
;; This module fetches from that backend with auto_decompress enabled.
;; The backend must return Content-Encoding: gzip with a gzip body.
;;
;; Required fastly.toml:
;;   [local_server.backends.gzip-origin]
;;   url = "http://127.0.0.1:7878"
;;
;; The backend server must return a gzip-compressed response.
;; Expected: demonstrates both issues when processing gzipped responses.

(module
  (import "fastly_http_req" "body_downstream_get"
    (func $req_body_downstream_get (param i32 i32) (result i32)))
  (import "fastly_http_req" "new"
    (func $req_new (param i32) (result i32)))
  (import "fastly_http_req" "send"
    (func $req_send (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_http_req" "auto_decompress_response_set"
    (func $req_auto_decompress (param i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $resp_send_downstream (param i32 i32 i32) (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new (param i32) (result i32)))

  (memory (export "memory") 1)

  ;; Backend name at offset 0
  (data (i32.const 0) "gzip-origin")

  ;; Output slots
  ;; downstream req: 100, downstream body: 104
  ;; new req: 108, new body: 112
  ;; resp: 116, resp body: 120

  (func (export "_start")
    ;; Get downstream request
    (call $req_body_downstream_get (i32.const 100) (i32.const 104))
    drop

    ;; Create a new request
    (call $req_new (i32.const 108))
    drop

    ;; Enable auto-decompression (content_gzip = 1)
    (call $req_auto_decompress
      (i32.load (i32.const 108))
      (i32.const 1)  ;; CONTENT_GZIP flag
    )
    drop

    ;; Create empty body for the request
    (call $body_new (i32.const 112))
    drop

    ;; Send to backend - auto-decompress will process gzipped response
    (call $req_send
      (i32.load (i32.const 108))
      (i32.load (i32.const 112))
      (i32.const 0)    ;; backend name ptr
      (i32.const 11)   ;; backend name len
      (i32.const 116)  ;; resp handle out
      (i32.const 120)  ;; resp body handle out
    )
    drop

    ;; Forward the (decompressed) response to the client
    (call $resp_send_downstream
      (i32.load (i32.const 116))
      (i32.load (i32.const 120))
      (i32.const 0)
    )
    drop
  )
)
