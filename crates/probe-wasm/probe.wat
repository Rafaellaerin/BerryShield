(module
  ;; Human-readable reference module used by protocol tests and reviewers.
  ;; Production builds are produced from src/lib.rs with wasm-pack.
  (func $mix32 (param $x i32) (result i32)
    local.get $x
    local.get $x
    i32.const 16
    i32.shr_u
    i32.xor
    local.tee $x
    i32.const 2146121005
    i32.mul
    local.tee $x
    local.get $x
    i32.const 15
    i32.shr_u
    i32.xor
    local.tee $x
    i32.const 2221713035
    i32.mul
    local.tee $x
    local.get $x
    i32.const 16
    i32.shr_u
    i32.xor)
  (export "mix32" (func $mix32))
)
