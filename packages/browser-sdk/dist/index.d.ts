import type { BerryShieldOptions } from "./types.js";
export declare class BerryShield {
    private readonly siteKey;
    private readonly endpoint;
    private readonly timeoutMs;
    private readonly wasmProbeUrl?;
    private readonly interactiveContainer?;
    private readonly behavior;
    private readonly sessionID;
    constructor(options: BerryShieldOptions);
    execute(action: string): Promise<string>;
    destroy(): void;
    private post;
}
export type { BerryShieldOptions, ChallengeResponse } from "./types.js";
