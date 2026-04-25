;; PoC for finding 040: Large memory offsets panic on checked addition
;;
;; In src/shift_mem.rs:140, load/store instruction offsets are shifted by
;; OFFSET (131072). When the original offset > u32::MAX - 131072 = 4294836223,
;; checked_add overflows and unwrap() panics.
;;
;; Trigger: run through component adaptation (viceroy adapt or adapt_component(true))

(module
  (memory (export "memory") 1)

  (func (export "_start")
    ;; Load with an offset just above the overflow threshold
    ;; 4294836224 = 0xFFFE0000 > u32::MAX - 131072
    i32.const 0
    i32.load offset=4294836224
    drop
  )
)
