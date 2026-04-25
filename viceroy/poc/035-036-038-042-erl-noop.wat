;; PoC for findings 035, 036, 038, 042: ERL APIs are all no-ops
;;
;; 035: check_rate always returns false/0 (never blocks)
;; 036: ratecounter_increment and penaltybox_add silently discard mutations
;; 038: penaltybox_has always returns false/0 (never enforces)
;; 042: All state-changing ERL APIs are no-ops returning success
;;
;; This module demonstrates that rate limiting is completely non-functional:
;; it increments a counter 1000 times, adds to penalty box, then checks
;; both -- the counter is always 0 and penalty box is always empty.
;;
;; Trigger: serve this module and send any HTTP request.
;; Expected: HTTP 200 with body "PASS" (all checks confirm no-op behavior),
;;   demonstrating that rate limiting provides zero protection.

(module
  (import "fastly_erl" "check_rate"
    (func $erl_check_rate
      (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_erl" "ratecounter_increment"
    (func $erl_ratecounter_increment (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_erl" "penaltybox_add"
    (func $erl_penaltybox_add (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_erl" "penaltybox_has"
    (func $erl_penaltybox_has (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_erl" "ratecounter_lookup_count"
    (func $erl_ratecounter_lookup_count (param i32 i32 i32 i32 i32 i32) (result i32)))

  (import "fastly_http_resp" "new"
    (func $resp_new (param i32) (result i32)))
  (import "fastly_http_resp" "status_set"
    (func $resp_status_set (param i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $resp_send_downstream (param i32 i32 i32) (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new (param i32) (result i32)))
  (import "fastly_http_body" "write"
    (func $body_write (param i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; Strings
  (data (i32.const 0) "my-counter")   ;; 10 bytes
  (data (i32.const 16) "my-penaltybox") ;; 13 bytes
  (data (i32.const 32) "attacker-ip")  ;; 11 bytes
  (data (i32.const 48) "PASS")         ;; 4 bytes
  (data (i32.const 56) "FAIL")         ;; 4 bytes

  ;; Output slots
  ;; blocked_out: offset 100
  ;; has_out: offset 104
  ;; count_out: offset 108
  ;; resp handle: offset 200
  ;; body handle: offset 204
  ;; nwritten: offset 208

  (func (export "_start")
    (local $i i32)
    (local $resp i32)
    (local $body i32)

    ;; Increment the rate counter 1000 times
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (i32.const 1000)))
        (call $erl_ratecounter_increment
          (i32.const 0) (i32.const 10)    ;; counter name
          (i32.const 32) (i32.const 11)   ;; entry
          (i32.const 1)                   ;; delta
        )
        drop
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )

    ;; Add entry to penalty box with 60s TTL
    (call $erl_penaltybox_add
      (i32.const 16) (i32.const 13)   ;; penalty box name
      (i32.const 32) (i32.const 11)   ;; entry
      (i32.const 60)                  ;; TTL
    )
    drop

    ;; Check rate: window=10s, limit=1 (should be WAY over limit)
    (call $erl_check_rate
      (i32.const 0) (i32.const 10)    ;; counter name
      (i32.const 32) (i32.const 11)   ;; entry
      (i32.const 1)                   ;; delta
      (i32.const 10)                  ;; window (10s)
      (i32.const 1)                   ;; limit (1 req!)
      (i32.const 16) (i32.const 13)   ;; penalty box name
      (i32.const 60)                  ;; TTL
      (i32.const 100)                 ;; blocked_out
    )
    drop

    ;; Check penalty box membership
    (call $erl_penaltybox_has
      (i32.const 16) (i32.const 13)   ;; penalty box name
      (i32.const 32) (i32.const 11)   ;; entry
      (i32.const 104)                 ;; has_out
    )
    drop

    ;; Lookup count
    (call $erl_ratecounter_lookup_count
      (i32.const 0) (i32.const 10)    ;; counter name
      (i32.const 32) (i32.const 11)   ;; entry
      (i32.const 10)                  ;; duration (10s)
      (i32.const 108)                 ;; count_out
    )
    drop

    ;; Create response
    (call $resp_new (i32.const 200))
    drop
    (local.set $resp (i32.load (i32.const 200)))
    (call $body_new (i32.const 204))
    drop
    (local.set $body (i32.load (i32.const 204)))

    ;; If blocked=0 AND has=0 AND count=0, all three confirm no-op -> PASS
    ;; (After 1000 increments with limit=1, these should all be nonzero
    ;;  in a real implementation)
    (if (i32.and
          (i32.and
            (i32.eqz (i32.load (i32.const 100)))  ;; blocked = 0
            (i32.eqz (i32.load (i32.const 104)))   ;; has = 0
          )
          (i32.eqz (i32.load (i32.const 108)))     ;; count = 0
        )
      (then
        ;; PASS: everything is a no-op as expected
        (call $resp_status_set (local.get $resp) (i32.const 200))
        drop
        (call $body_write
          (local.get $body) (i32.const 48) (i32.const 4) (i32.const 0) (i32.const 208))
        drop
      )
      (else
        ;; FAIL: some ERL function actually did something
        (call $resp_status_set (local.get $resp) (i32.const 500))
        drop
        (call $body_write
          (local.get $body) (i32.const 56) (i32.const 4) (i32.const 0) (i32.const 208))
        drop
      )
    )

    (call $resp_send_downstream (local.get $resp) (local.get $body) (i32.const 0))
    drop
  )
)
