use crate::model::{RiskInput, ScoreResponse, SitePolicy};

pub fn score(input: &RiskInput, site: &SitePolicy) -> ScoreResponse {
    let c = &input.telemetry.client;
    let b = &c.behavior;
    let mut value = 0.0_f64;
    let mut tags: Vec<&'static str> = Vec::new();

    let mut add = |points: f64, tag: &'static str| {
        value += points;
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    };

    if c.webdriver {
        add(32.0, "webdriver-exposed");
    }
    if input.user_agent.trim().is_empty() || c.user_agent.trim().is_empty() {
        add(18.0, "missing-user-agent");
    }
    let ua = format!("{} {}", input.user_agent, c.user_agent).to_ascii_lowercase();
    if ["headlesschrome", "phantomjs", "python-requests", "curl/", "wget/"]
        .iter()
        .any(|needle| ua.contains(needle))
    {
        add(30.0, "automation-user-agent");
    }
    if !c.secure_context {
        add(5.0, "non-secure-context");
    }
    if !c.webcrypto_available {
        add(5.0, "webcrypto-unavailable");
    }
    if !c.wasm_available {
        add(3.0, "wasm-unavailable");
    }
    if c.hardware_concurrency < 0 || c.hardware_concurrency > 256 {
        add(10.0, "invalid-hardware-concurrency");
    }
    if c.screen_width_bucket < 0 || c.screen_height_bucket < 0 {
        add(8.0, "invalid-screen");
    }
    if c.languages.is_empty() && !input.accept_language.trim().is_empty() {
        add(5.0, "language-inconsistency");
    }
    if !c.platform.is_empty() && !input.sec_ch_platform.is_empty() {
        let a = platform(&c.platform);
        let h = platform(&input.sec_ch_platform);
        if !a.is_empty() && !h.is_empty() && a != h {
            add(12.0, "platform-inconsistency");
        }
    }

    // Accessibility-safe weighting: lack of pointer movement is never enough
    // by itself to block or force a visual puzzle.
    if b.dwell_ms > 1500 && b.pointer_events == 0 && b.key_events == 0 {
        add(4.0, "no-observed-interaction");
    }
    if b.pointer_events > 5000 && b.dwell_ms < 1000 {
        add(8.0, "impossible-pointer-density");
    }
    if !b.pointer_variance.is_finite() {
        add(15.0, "invalid-behavior-metrics");
    }

    if input.reputation.score > 0 {
        add(input.reputation.score as f64 * 0.48, "network-reputation");
    }
    if input.reputation.tor {
        add(22.0, "tor-exit");
    }
    if input.reputation.hosting {
        add(10.0, "hosting-network");
    }
    if input.reputation.proxy || input.reputation.vpn {
        add(7.0, "proxy-or-vpn");
    }
    if input.reputation.abuse_score >= 80 {
        add(12.0, "high-abuse-score");
    }
    if input.request_rate > site.rate_limit_per_minute / 2 {
        add(8.0, "elevated-request-rate");
    }

    let n = value.round().clamp(0.0, 100.0) as i64;
    let decision = if n >= site.thresholds.block {
        "block"
    } else if n >= site.thresholds.interactive {
        "interactive"
    } else if n >= site.thresholds.pow {
        "pow"
    } else {
        "allow"
    };
    ScoreResponse { score: n, decision, tags }
}

fn platform(v: &str) -> &'static str {
    let x = v.trim_matches(&['"', '\'', ' '][..]).to_ascii_lowercase();
    if x.contains("win") {
        "windows"
    } else if x.contains("mac") {
        "macos"
    } else if x.contains("android") {
        "android"
    } else if x.contains("ios") || x.contains("iphone") || x.contains("ipad") {
        "ios"
    } else if x.contains("linux") {
        "linux"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn policy() -> SitePolicy {
        SitePolicy {
            rate_limit_per_minute: 60,
            thresholds: Thresholds { pow: 30, interactive: 62, block: 92 },
        }
    }

    #[test]
    fn exposed_webdriver_escalates() {
        let mut input = RiskInput::default();
        input.user_agent = "Mozilla/5.0".into();
        input.telemetry.client.user_agent = "Mozilla/5.0".into();
        input.telemetry.client.webdriver = true;
        input.telemetry.client.secure_context = true;
        input.telemetry.client.webcrypto_available = true;
        input.telemetry.client.wasm_available = true;
        let out = score(&input, &policy());
        assert_ne!(out.decision, "allow");
    }
}
