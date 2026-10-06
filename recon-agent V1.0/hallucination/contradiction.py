"""矛盾检测（HARD：多源冲突标 [冲突，需人工核实]，禁止 LLM 二选一）。"""
from __future__ import annotations

CONFLICT_TAG = "[冲突，需人工核实]"


class ContradictionDetector:
    """登记 (主体, 属性, 值, 来源)，同主体同属性出现不同值即为冲突。"""

    def __init__(self) -> None:
        self._observations: dict[str, dict[str, dict[str, str]]] = {}

    def observe(self, subject: str, attribute: str, value: str, source: str) -> None:
        """登记一次观察（值统一小写归一后比较）。"""
        if not value:
            return
        subject_map = self._observations.setdefault(subject.lower(), {})
        value_map = subject_map.setdefault(attribute.lower(), {})
        if not value_map:
            value_map[value] = source
            return
        first_value = next(iter(value_map))
        if value.lower() != first_value.lower() and value.lower() not in {v.lower() for v in value_map}:
            value_map[value] = source  # 保留冲突双方，不覆盖、不裁决

    def conflicts(self) -> list[dict]:
        """返回冲突清单：{subject, attribute, values}。"""
        out: list[dict] = []
        for subject, attrs in self._observations.items():
            for attribute, values in attrs.items():
                if len(values) > 1:
                    out.append({
                        "subject": subject,
                        "attribute": attribute,
                        "values": dict(values),
                        "tag": CONFLICT_TAG,
                    })
        return out
