;; PoC for finding 039: Valid multi-memory modules panic during rewrite
;;
;; The shift_main_module function in src/shift_mem.rs:192 asserts
;; module.memories.len() == 1. A valid multi-memory Wasm module causes
;; a host panic during the component adaptation step.
;;
;; Trigger: run through component adaptation (viceroy adapt or adapt_component(true))

(module
  (memory 1)
  (memory 1)

  (func (export "_start")
    nop
  )

  (export "memory" (memory 0))
)
