;; PoC for finding 041: Supported Wasm instructions hit todo!() panic
;;
;; In src/shift_mem.rs:161-166, atomic and SIMD memory instructions
;; are matched with todo!(), causing an unconditional panic.
;;
;; Trigger: run through component adaptation (viceroy adapt or adapt_component(true))
;;
;; Note: This module requires the threads proposal (shared memory + atomics).

(module
  (memory (export "memory") 1 1 shared)

  (func (export "_start")
    (drop
      (i32.atomic.rmw.add
        (i32.const 0)
        (i32.const 1)
      )
    )
  )
)
