import type { BehaviorSignals } from "./types.js";

export class BehaviorMonitor {
  private readonly started = performance.now();
  private pointerEvents = 0;
  private pointerDistance = 0;
  private pointerSpeeds: number[] = [];
  private lastPointer?: { x: number; y: number; t: number };
  private keyTimes: number[] = [];
  private focusTransitions = 0;
  private visibilityChanges = 0;
  private disposers: Array<() => void> = [];

  constructor() {
    const onPointer = (event: PointerEvent) => {
      const t = performance.now();
      this.pointerEvents++;
      if (this.lastPointer) {
        const dx = event.clientX - this.lastPointer.x;
        const dy = event.clientY - this.lastPointer.y;
        const distance = Math.hypot(dx, dy);
        const dt = Math.max(1, t - this.lastPointer.t);
        this.pointerDistance += distance;
        this.pointerSpeeds.push(distance / dt);
        if (this.pointerSpeeds.length > 128) this.pointerSpeeds.shift();
      }
      this.lastPointer = { x: event.clientX, y: event.clientY, t };
    };
    const onKey = () => {
      this.keyTimes.push(performance.now());
      if (this.keyTimes.length > 64) this.keyTimes.shift();
    };
    const onFocus = () => this.focusTransitions++;
    const onVisibility = () => this.visibilityChanges++;

    window.addEventListener("pointermove", onPointer, { passive: true });
    window.addEventListener("keydown", onKey, { passive: true });
    window.addEventListener("focus", onFocus, { passive: true });
    window.addEventListener("blur", onFocus, { passive: true });
    document.addEventListener("visibilitychange", onVisibility, { passive: true });

    this.disposers = [
      () => window.removeEventListener("pointermove", onPointer),
      () => window.removeEventListener("keydown", onKey),
      () => window.removeEventListener("focus", onFocus),
      () => window.removeEventListener("blur", onFocus),
      () => document.removeEventListener("visibilitychange", onVisibility),
    ];
  }

  snapshot(): BehaviorSignals {
    const intervals = this.keyTimes.slice(1).map((t, i) => t - this.keyTimes[i]);
    return {
      dwell_ms: Math.round(performance.now() - this.started),
      pointer_events: this.pointerEvents,
      pointer_distance: round(this.pointerDistance),
      pointer_variance: round(stddev(this.pointerSpeeds)),
      key_events: this.keyTimes.length,
      key_interval_mean_ms: round(mean(intervals)),
      key_interval_std_ms: round(stddev(intervals)),
      focus_transitions: this.focusTransitions,
      visibility_changes: this.visibilityChanges,
    };
  }

  stop(): void {
    for (const dispose of this.disposers) dispose();
    this.disposers = [];
  }
}

function mean(values: number[]): number {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
}

function stddev(values: number[]): number {
  if (values.length < 2) return 0;
  const m = mean(values);
  return Math.sqrt(values.reduce((acc, value) => acc + (value - m) ** 2, 0) / values.length);
}

function round(value: number): number {
  return Number.isFinite(value) ? Math.round(value * 1000) / 1000 : 0;
}
