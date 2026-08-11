import { BehaviorMonitor } from "./behavior.js";
import { collectSignals } from "./collector.js";
import { runHoldChallenge } from "./interactive.js";
import { solvePow } from "./pow.js";
export class BerryShield {
    siteKey;
    endpoint;
    timeoutMs;
    wasmProbeUrl;
    interactiveContainer;
    behavior = new BehaviorMonitor();
    sessionID = randomID("bss_");
    constructor(options) {
        if (!options.siteKey)
            throw new Error("BerryShield siteKey is required");
        this.siteKey = options.siteKey;
        this.endpoint = (options.endpoint || "http://localhost:8080").replace(/\/$/, "");
        this.timeoutMs = options.timeoutMs || 15_000;
        this.wasmProbeUrl = options.wasmProbeUrl;
        this.interactiveContainer = options.interactiveContainer;
    }
    async execute(action) {
        if (!/^[A-Za-z0-9_.:/-]{1,64}$/.test(action))
            throw new Error("invalid BerryShield action");
        const telemetry = { client: await collectSignals(this.behavior, this.wasmProbeUrl) };
        const challenge = await this.post("/v1/challenge", {
            site_key: this.siteKey,
            action,
            hostname: location.hostname,
            session_id: this.sessionID,
            telemetry,
        });
        if (challenge.decision === "block")
            throw new Error("BerryShield blocked this request");
        if (challenge.decision === "allow" && challenge.token)
            return challenge.token;
        if (!challenge.challenge_id || !challenge.kind)
            throw new Error("invalid challenge response");
        let proof;
        if (challenge.kind === "pow") {
            const seed = String(challenge.params?.seed || "");
            const bits = Number(challenge.params?.difficulty_bits || 16);
            const maxNonce = Number(challenge.params?.max_nonce || 20_000_000);
            const nonce = await solvePow(seed, bits, maxNonce, Math.min(12_000, this.timeoutMs));
            proof = { kind: "pow", nonce };
        }
        else {
            const hold = await runHoldChallenge(challenge.params || {}, this.behavior, this.interactiveContainer);
            const seed = String(challenge.params?.pow_seed || "");
            const bits = Number(challenge.params?.pow_bits || 14);
            const maxNonce = Number(challenge.params?.pow_max_nonce || 10_000_000);
            const nonce = await solvePow(seed, bits, maxNonce, Math.min(8_000, this.timeoutMs));
            proof = { ...hold, nonce };
        }
        const result = await this.post(`/v1/challenge/${encodeURIComponent(challenge.challenge_id)}/verify`, { session_id: this.sessionID, proof });
        if (!result.success || !result.token)
            throw new Error(result.error || "challenge verification failed");
        return result.token;
    }
    destroy() {
        this.behavior.stop();
    }
    async post(path, body) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const response = await fetch(this.endpoint + path, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-BerryShield-Site-Key": this.siteKey,
                },
                credentials: "omit",
                cache: "no-store",
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(data.error || `BerryShield HTTP ${response.status}`);
            }
            return data;
        }
        finally {
            clearTimeout(timer);
        }
    }
}
function randomID(prefix) {
    const bytes = crypto.getRandomValues(new Uint8Array(18));
    const encoded = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return prefix + encoded;
}
