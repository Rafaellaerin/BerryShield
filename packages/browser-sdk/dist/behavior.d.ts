import type { BehaviorSignals } from "./types.js";
export declare class BehaviorMonitor {
    private readonly started;
    private pointerEvents;
    private pointerDistance;
    private pointerSpeeds;
    private lastPointer?;
    private keyTimes;
    private focusTransitions;
    private visibilityChanges;
    private disposers;
    constructor();
    snapshot(): BehaviorSignals;
    stop(): void;
}
