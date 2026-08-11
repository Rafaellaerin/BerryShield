# Browser probe WebAssembly

Build:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build --target web --release
```

The probe deliberately exports only low-value environmental computations. BerryShield
does not treat a WASM result as a secret; it combines it with server-observed signals,
rate state, reputation, challenge state and single-use server verification.
