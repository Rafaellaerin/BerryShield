export function runHoldChallenge(params, behavior, container) {
    const minHold = Number(params.min_hold_ms || 850);
    const maxHold = Number(params.max_hold_ms || 7000);
    return new Promise((resolve, reject) => {
        const host = container || document.body;
        const root = document.createElement("div");
        root.setAttribute("role", "dialog");
        root.setAttribute("aria-label", "BerryShield verification");
        root.style.cssText =
            "position:fixed;inset:0;z-index:2147483646;background:rgba(10,14,23,.72);" +
                "display:grid;place-items:center;font-family:system-ui,sans-serif";
        const card = document.createElement("div");
        card.style.cssText =
            "width:min(92vw,420px);background:#111827;color:#fff;border:1px solid #334155;" +
                "border-radius:16px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.4)";
        const title = document.createElement("div");
        title.textContent = "Verificação BerryShield";
        title.style.cssText = "font-size:18px;font-weight:700;margin-bottom:8px";
        const hint = document.createElement("div");
        hint.textContent = "Segure o botão por um instante. Teclado: Enter ou Espaço.";
        hint.style.cssText = "font-size:14px;opacity:.8;margin-bottom:18px;line-height:1.4";
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = "Segure para verificar";
        button.style.cssText =
            "width:100%;padding:14px 16px;border:0;border-radius:12px;cursor:pointer;" +
                "font-size:15px;font-weight:700;background:#e11d48;color:#fff;touch-action:none";
        const status = document.createElement("div");
        status.setAttribute("aria-live", "polite");
        status.style.cssText = "height:20px;margin-top:12px;font-size:13px;opacity:.85";
        card.append(title, hint, button, status);
        root.append(card);
        host.append(root);
        let started = 0;
        let active = false;
        let events = 0;
        let timer = 0;
        const begin = (event) => {
            event?.preventDefault();
            if (active)
                return;
            active = true;
            events++;
            started = performance.now();
            button.textContent = "Continue segurando…";
            status.textContent = "";
            timer = window.setTimeout(() => finish(), minHold);
        };
        const cancel = (event) => {
            event?.preventDefault();
            if (!active)
                return;
            events++;
            active = false;
            clearTimeout(timer);
            const elapsed = performance.now() - started;
            if (elapsed < minHold) {
                button.textContent = "Segure para verificar";
                status.textContent = "Soltou cedo demais; tente novamente.";
            }
        };
        const finish = () => {
            if (!active)
                return;
            const elapsed = Math.round(performance.now() - started);
            active = false;
            clearTimeout(timer);
            events++;
            if (elapsed > maxHold) {
                root.remove();
                reject(new Error("interactive challenge timed out"));
                return;
            }
            button.textContent = "Verificado";
            const snap = behavior.snapshot();
            const proof = {
                kind: "interactive",
                hold_ms: elapsed,
                event_count: Math.max(2, events + snap.key_events + Math.min(8, snap.pointer_events)),
                pointer_variance: snap.pointer_variance,
            };
            setTimeout(() => root.remove(), 120);
            resolve(proof);
        };
        button.addEventListener("pointerdown", begin);
        button.addEventListener("pointerup", () => {
            if (performance.now() - started >= minHold)
                finish();
            else
                cancel();
        });
        button.addEventListener("pointercancel", cancel);
        button.addEventListener("keydown", (e) => {
            if (e.key === " " || e.key === "Enter")
                begin(e);
        });
        button.addEventListener("keyup", (e) => {
            if (e.key === " " || e.key === "Enter") {
                if (performance.now() - started >= minHold)
                    finish();
                else
                    cancel(e);
            }
        });
        button.focus();
    });
}
