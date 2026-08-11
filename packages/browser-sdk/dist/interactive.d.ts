import type { BehaviorMonitor } from "./behavior.js";
export interface HoldProof {
    kind: "interactive";
    hold_ms: number;
    event_count: number;
    pointer_variance: number;
    nonce?: number;
}
export declare function runHoldChallenge(params: Record<string, unknown>, behavior: BehaviorMonitor, container?: HTMLElement): Promise<HoldProof>;
