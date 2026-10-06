"""输出一致性校验（HARD：报告中"有、证据里没有"的条目自动标 [无证据] 或移除）。"""
from __future__ import annotations

from pydantic import BaseModel, Field

NO_EVIDENCE_TAG = "[无证据]"


class Finding(BaseModel):
    """待写入报告的单条结论。"""

    subject: str
    claim: str
    evidence: list[str] = Field(default_factory=list)  # 来源清单（须与证据登记簿对应）
    confidence: float = 1.0


class ConsistencyReport(BaseModel):
    """一致性校验结果。"""

    kept: list[Finding] = Field(default_factory=list)
    flagged: list[Finding] = Field(default_factory=list)
    removed: list[Finding] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        """CI 模式下存在被移除项即阻断（HARD 可配置）。"""
        return not self.removed


class OutputConsistencyChecker:
    """报告生成前的最后一道抗幻觉防线。"""

    def __init__(self, known_sources: set[str]) -> None:
        self._known = {s for s in known_sources if s}

    def check(self, findings: list[Finding], remove_unsourced: bool = False) -> ConsistencyReport:
        """逐条校验：evidence 为空或全部未知 → 标注或移除。"""
        report = ConsistencyReport()
        for finding in findings:
            valid = [e for e in finding.evidence if e in self._known]
            if finding.evidence and valid:
                report.kept.append(finding.model_copy(update={"evidence": valid}))
            elif finding.evidence:
                report.flagged.append(finding.model_copy(
                    update={"evidence": valid, "claim": f"{finding.claim} {NO_EVIDENCE_TAG}"}
                ))
            else:
                marked = finding.model_copy(update={"claim": f"{finding.claim} {NO_EVIDENCE_TAG}"})
                if remove_unsourced:
                    report.removed.append(finding)
                else:
                    report.flagged.append(marked)
        return report
