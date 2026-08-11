use wasm_bindgen::prelude::*;

/// Small deterministic mixer used as one of several non-secret browser probes.
/// This is not a cryptographic primitive and is never trusted as an authenticator.
#[wasm_bindgen]
pub fn mix32(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^ (x >> 16)
}

/// Summarizes monotonic timing deltas without retaining the raw samples.
/// Raw high-resolution timing data stays in the browser.
#[wasm_bindgen]
pub fn timing_summary(samples: &[f64]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mut mean = 0.0;
    for value in samples {
        mean += *value;
    }
    mean /= samples.len() as f64;

    let mut variance = 0.0;
    for value in samples {
        let d = *value - mean;
        variance += d * d;
    }
    (variance / samples.len() as f64).sqrt()
}
