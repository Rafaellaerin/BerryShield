from dataclasses import dataclass, field, asdict
from typing import Iterable


@dataclass(slots=True)
class ProviderResult:
    provider: str
    score: int = 0
    proxy: bool = False
    vpn: bool = False
    tor: bool = False
    hosting: bool = False
    abuse_score: int = 0
    country: str = ""
    asn: str = ""
    warning: str = ""

    def normalized(self) -> "ProviderResult":
        self.score = max(0, min(100, int(self.score)))
        self.abuse_score = max(0, min(100, int(self.abuse_score)))
        return self


@dataclass(slots=True)
class Reputation:
    score: int = 0
    proxy: bool = False
    vpn: bool = False
    tor: bool = False
    hosting: bool = False
    abuse_score: int = 0
    country: str = ""
    asn: str = ""
    providers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def aggregate(results: Iterable[ProviderResult]) -> Reputation:
    items = [x.normalized() for x in results]
    good = [x for x in items if not x.warning]
    warnings = [f"{x.provider}:{x.warning}" for x in items if x.warning]
    if not good:
        return Reputation(warnings=warnings)

    # Max-plus-consensus: one strong provider can escalate, while agreement
    # between multiple providers adds a small confidence premium.
    scores = sorted((x.score for x in good), reverse=True)
    top = scores[0]
    consensus = sum(scores[1:3]) / max(1, min(2, len(scores) - 1)) if len(scores) > 1 else 0
    combined = min(100, round(top * 0.75 + consensus * 0.25))

    abuse = max((x.abuse_score for x in good), default=0)
    country = next((x.country for x in good if x.country), "")
    asn = next((x.asn for x in good if x.asn), "")
    return Reputation(
        score=combined,
        proxy=any(x.proxy for x in good),
        vpn=any(x.vpn for x in good),
        tor=any(x.tor for x in good),
        hosting=any(x.hosting for x in good),
        abuse_score=abuse,
        country=country,
        asn=asn,
        providers=[x.provider for x in good],
        warnings=warnings,
    )
