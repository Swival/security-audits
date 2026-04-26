;; PoC for finding 041 (variant): SIMD load instructions hit todo!() panic
;;
;; In src/shift_mem.rs:166, LoadSimd instructions trigger todo!().
;;
;; Trigger: run through component adaptation (viceroy adapt or adapt_component(true))

(module
  (memory (export "memory") 1)

  (func (export "_start")
    (drop
      (v128.load (i32.const 0))
    )
  )
)
