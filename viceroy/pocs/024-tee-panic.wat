;; PoC for finding 024: Known-size tee panics on body read error
;;
;; In src/body_tee.rs:73-75, when a body has an exact size hint
;; (from Content-Length), the tee function uses:
;;   hyper::body::to_bytes(hyper_body).await.expect("Failed to buffer")
;;
;; If the client disconnects before sending all the bytes promised by
;; Content-Length, to_bytes() returns Err and expect() panics.
;;
;; Trigger: serve this module, send a request with
;;   Content-Length: 1000000
;; but close the connection immediately after headers (send 0 bytes
;; of the promised body). The tee operation on the body will panic.
;;
;; This module reads the downstream body which has Content-Length set,
;; and tries to use it in a way that triggers the tee path (e.g.,
;; sending it to a backend while also reading it).

(module
  (import "fastly_http_req" "body_downstream_get"
    (func $req_body_downstream_get (param i32 i32) (result i32)))
  (import "fastly_http_req" "new"
    (func $req_new (param i32) (result i32)))
  (import "fastly_http_req" "send"
    (func $req_send (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_http_resp" "new"
    (func $resp_new (param i32) (result i32)))
  (import "fastly_http_resp" "status_set"
    (func $resp_status_set (param i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $resp_send_downstream (param i32 i32 i32) (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new (param i32) (result i32)))

  (memory (export "memory") 1)

  ;; Backend name
  (data (i32.const 0) "origin")

  ;; Output slots: req=100, body=104, new_req=108
  ;; resp=112, resp_body=116, new_body=120

  (func (export "_start")
    ;; Get downstream request with its body
    ;; The body has Content-Length but the connection may be cut short
    (call $req_body_downstream_get (i32.const 100) (i32.const 104))
    drop

    ;; Create new request to forward
    (call $req_new (i32.const 108))
    drop

    ;; Forward the downstream body to the backend
    ;; This triggers tee() if the body needs to be read in multiple places
    ;; The tee's to_bytes().expect() will panic if the body read fails
    (call $req_send
      (i32.load (i32.const 108))
      (i32.load (i32.const 104))  ;; downstream body (may be truncated)
      (i32.const 0)               ;; backend name
      (i32.const 6)               ;; backend name len
      (i32.const 112)             ;; resp handle out
      (i32.const 116)             ;; resp body out
    )
    drop

    ;; Forward response
    (call $resp_send_downstream
      (i32.load (i32.const 112))
      (i32.load (i32.const 116))
      (i32.const 0)
    )
    drop
  )
)
