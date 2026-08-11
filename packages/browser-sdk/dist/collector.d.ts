import type { ClientSignals } from "./types.js";
import { BehaviorMonitor } from "./behavior.js";
export declare function collectSignals(behavior: BehaviorMonitor, wasmProbeUrl?: string): Promise<ClientSignals>;
