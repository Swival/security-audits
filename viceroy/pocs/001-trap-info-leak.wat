;; PoC for finding 001: Trap details returned in HTTP 500 body
;;
;; When a guest traps, exec_err_to_response (src/execute.rs:1071) converts the
;; WasmTrap into an HTTP 500 response whose body contains the full debug
;; representation including Wasm backtraces. This leaks internal details
;; to the HTTP client.
;;
;; Trigger: send any HTTP request to Viceroy serving this module.
;; Expected: HTTP 500 response body contains trap details and backtrace.

(module
  (func (export "_start")
    unreachable
  )
)
