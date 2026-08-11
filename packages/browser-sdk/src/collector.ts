import type { ClientSignals } from "./types.js";
import { BehaviorMonitor } from "./behavior.js";

const SDK_VERSION = "0.1.0";

export async function collectSignals(
  behavior: BehaviorMonitor,
  wasmProbeUrl?: string,
): Promise<ClientSignals> {
  const gl = webglInfo();
  const [vendorHash, rendererHash] = await Promise.all([
    shortHash(gl.vendor),
    shortHash(gl.renderer),
  ]);
  const wasm = await runWasmProbe(wasmProbeUrl);

  return {
    sdk_version: SDK_VERSION,
    user_agent: navigator.userAgent || "",
    platform: navigator.platform || "",
    languages: Array.from(navigator.languages || []),
    timezone: safeTimezone(),
    screen_width_bucket: bucket(screen?.width || 0, 100),
    screen_height_bucket: bucket(screen?.height || 0, 100),
    color_depth: screen?.colorDepth || 0,
    hardware_concurrency: navigator.hardwareConcurrency || 0,
    device_memory_gb: Number((navigator as Navigator & { deviceMemory?: number }).deviceMemory || 0),
    max_touch_points: navigator.maxTouchPoints || 0,
    webdriver: navigator.webdriver === true,
    secure_context: window.isSecureContext,
    cookie_enabled: navigator.cookieEnabled,
    local_storage_ok: storageWorks("localStorage"),
    session_storage_ok: storageWorks("sessionStorage"),
    webgl_vendor_hash: vendorHash || undefined,
    webgl_renderer_hash: rendererHash || undefined,
    wasm_available: typeof WebAssembly === "object",
    wasm_mix: wasm,
    webcrypto_available: !!globalThis.crypto?.subtle,
    performance_jitter: performanceJitter(),
    behavior: behavior.snapshot(),
  };
}

function bucket(value: number, size: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.round(value / size) * size;
}

function safeTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    return "";
  }
}

function storageWorks(name: "localStorage" | "sessionStorage"): boolean {
  try {
    const storage = window[name];
    const key = "__berryshield_probe__";
    storage.setItem(key, "1");
    storage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

function webglInfo(): { vendor: string; renderer: string } {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl");
    if (!gl) return { vendor: "", renderer: "" };
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    if (!ext) return { vendor: "", renderer: "" };
    return {
      vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || ""),
      renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || ""),
    };
  } catch {
    return { vendor: "", renderer: "" };
  }
}

async function shortHash(value: string): Promise<string> {
  if (!value || !crypto?.subtle) return "";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest).slice(0, 8))
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}

function performanceJitter(): number {
  try {
    const values: number[] = [];
    let last = performance.now();
    for (let i = 0; i < 32; i++) {
      const now = performance.now();
      values.push(Math.max(0, now - last));
      last = now;
    }
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, x) => a + (x - mean) ** 2, 0) / values.length;
    return Math.round(Math.sqrt(variance) * 1_000_000) / 1_000_000;
  } catch {
    return 0;
  }
}

async function runWasmProbe(url?: string): Promise<number | undefined> {
  if (!url || typeof WebAssembly !== "object") return undefined;
  try {
    const response = await fetch(url, { credentials: "omit", cache: "force-cache" });
    if (!response.ok) return undefined;
    const bytes = await response.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    const mix32 = instance.exports.mix32;
    if (typeof mix32 !== "function") return undefined;
    const seed = crypto.getRandomValues(new Uint32Array(1))[0];
    return Number((mix32 as (x: number) => number)(seed)) >>> 0;
  } catch {
    return undefined;
  }
}
