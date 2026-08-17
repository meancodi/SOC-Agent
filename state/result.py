from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationResult:
    incident_id: str
    status: str
    summary: str

    findings: list[dict[str, Any]] = field(
        default_factory=list
    )

    timeline: list[dict[str, Any]] = field(
        default_factory=list
    )

    conclusion: str = ""

    confidence: float = 0.0

    limitations: list[str] = field(
        default_factory=list
    )

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "summary": self.summary,
            "findings": self.findings,
            "timeline": self.timeline,
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "limitations": self.limitations
        }