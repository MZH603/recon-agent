"""三级扫描深度门控（HARD：L2 须三次独立确认 + 签名文件 + 逐项确认，不可绕过、不可持久化）。"""
from __future__ import annotations

import asyncio
import getpass
import hashlib
import json
import platform
import time
from pathlib import Path

from platforms.paths import get_auth_dir
from utils.logger import audit

ABORT_WORD = "abort"
GENERIC_YES = {"y", "yes", "确认", "是", "ok", "1", "true", "confirm"}
L2_STEP_CODE_1 = "CONFIRM 2"
L2_STEP_CODE_3 = "I UNDERSTAND AND AUTHORIZE"


class ScanGate:
    """扫描深度门控：L0 被动 / L1 一次确认 / L2 三次独立确认 + 签名 + 逐项确认。

    HARD:
    - batch_mode 或非 TTY 永久禁止 L2；--level 2 无 TTY 自动降级 L1 并报备；
    - 三级确认码不接受 y/yes/确认 等通用词；
    - 签名文件仅当次会话有效：构造时不读取任何旧签名，跨会话必须重签；
    - 任意环节输入 abort 立即退回 L0 且不可撤销。
    """

    def __init__(
        self,
        target: str,
        batch_mode: bool = False,
        is_tty: bool = True,
        requested_level: int = 0,
        auth_dir: Path | None = None,
        prompt_fn=None,
    ) -> None:
        self.target = target
        self.batch_mode = batch_mode
        self.is_tty = is_tty
        self._auth_dir = Path(auth_dir) if auth_dir else get_auth_dir()
        self._prompt_fn = prompt_fn or self._interactive_prompt
        self._aborted = False
        self._level = 0
        self._unlocked = False
        self._l2_next_step = 1
        self.confirm_log: list[dict] = []
        self.sig_path: Path | None = None
        self.downgrade_notice = ""
        # HARD: 非交互场景请求 L2 → 自动降级 L1 并报备
        if requested_level >= 2 and (batch_mode or not is_tty):
            self._level = 1
            self.downgrade_notice = "[门控] 非交互模式永久禁止 L2，已自动降级为 L1（HARD）"
        else:
            self._level = min(requested_level, 1)
        audit("gate_init", {"target": target, "requested": requested_level,
                            "batch": batch_mode, "tty": is_tty, "level": self._level})

    @property
    def level(self) -> int:
        """当前生效级别（abort 后恒为 0）。"""
        return 0 if self._aborted else self._level

    def current_level(self) -> int:
        return self.level

    # ---------- L1：一次确认 ----------
    async def request_level_1(self, purpose: str) -> bool:
        """L1 单次确认；batch/非 TTY 下无法交互确认，返回 False（只能由启动参数显式声明）。"""
        if self._aborted:
            return False
        if self._level >= 1:
            return True
        if self.batch_mode or not self.is_tty:
            return False
        text = await self._ask(
            f"[*] 请求进入 L1 隐蔽主动：{purpose}\n"
            "    [🔒] 隐蔽约束全程生效：限速 3-10s / 伪装 UA / 仅 TCP Connect / 失败不重试\n"
            "    输入 yes 授权（输入 abort 取消）："
        )
        answer = text.strip().lower()
        if answer == ABORT_WORD:
            self.abort()
            return False
        if answer in GENERIC_YES:
            self._level = 1
            self._log_confirm("level_1", text)
            return True
        return False

    # ---------- L2：三次独立确认 ----------
    async def request_level_2_step(self, step: int, plan: str = "") -> tuple[bool, str]:
        """L2 三级确认：step1 意图（CONFIRM 2）/ step2 目标精确串 / step3 责任声明。"""
        if self._aborted or self.batch_mode or not self.is_tty:
            return False, ""  # HARD: 非交互永久禁止 L2
        if step == 1:
            self._l2_next_step = 1
            text = await self._ask(
                f"[!] 进入 L2 需三次独立确认（当前 1/3）\n    本次计划：{plan}\n"
                f"    请输入 {L2_STEP_CODE_1} 继续（不接受 y/yes/确认）："
            )
            if text.strip() == L2_STEP_CODE_1:
                self._log_confirm("l2_step1", text)
                return True, text
            if text.strip().lower() == ABORT_WORD:
                self.abort()
            return False, text
        if step == 2:
            if self._l2_next_step != 2:
                return False, ""
            text = await self._ask(
                f"[2/3] 请输入授权目标精确字符串（输入 \"{self.target}\" 继续，防误确认）："
            )
            if text.strip() == self.target:
                self._log_confirm("l2_step2", text)
                return True, text
            if text.strip().lower() == ABORT_WORD:
                self.abort()
            return False, text
        if step == 3:
            if self._l2_next_step != 3:
                return False, ""
            text = await self._ask(
                "[3/3] 最终确认：L2 全部动作将逐项确认、可随时 abort 中止。\n"
                f"    输入 {L2_STEP_CODE_3} 解锁："
            )
            if text.strip() == L2_STEP_CODE_3:
                self._log_confirm("l2_step3", text)
                self.unlock_level_2()
                return True, text
            if text.strip().lower() == ABORT_WORD:
                self.abort()
            return False, text
        return False, ""

    def unlock_level_2(self) -> None:
        """生成签名文件 auth/<target-hash>.sig（HARD：SHA256 + 时间戳 + 操作者指纹）。"""
        operator = hashlib.sha256(
            f"{getpass.getuser()}@{platform.node()}".encode("utf-8")
        ).hexdigest()[:16]
        issued = time.strftime("%Y-%m-%dT%H:%M:%S")
        sig = hashlib.sha256(f"{self.target}|{operator}|{issued}".encode("utf-8")).hexdigest()
        self._auth_dir.mkdir(parents=True, exist_ok=True)
        target_key = hashlib.sha256(self.target.encode("utf-8")).hexdigest()
        self.sig_path = self._auth_dir / f"{target_key}.sig"
        self.sig_path.write_text(
            json.dumps({"target": self.target, "operator": operator,
                        "issued": issued, "sig": sig}, ensure_ascii=False, indent=2),
            encoding="utf-8", newline="",
        )
        self._unlocked = True
        self._level = 2
        audit("l2_unlocked", {"target": self.target, "operator": operator, "sig_prefix": sig[:16]})

    def verify_signature(self) -> bool:
        """校验本会话生成的签名文件（HARD：不匹配拒绝；跨会话因 _unlocked=False 直接无效）。"""
        if not self._unlocked or self.sig_path is None or not self.sig_path.exists():
            return False
        try:
            data = json.loads(self.sig_path.read_text(encoding="utf-8"))
            expected = hashlib.sha256(
                f"{data['target']}|{data['operator']}|{data['issued']}".encode("utf-8")
            ).hexdigest()
            return data.get("sig") == expected and data.get("target") == self.target
        except (OSError, ValueError, KeyError, TypeError):
            return False

    # ---------- L2：逐项确认 ----------
    async def confirm_step(self, action: str, command: str, risk: str) -> bool:
        """L2 每个具体动作执行前手动确认（HARD：解锁不等于免确认，不可批量 yes）。"""
        if self._aborted or self.batch_mode or not self.is_tty:
            return False
        text = await self._ask(
            f'<confirm level="2" action="{action}">\n'
            f"    命令: {command}\n    风险: {risk}\n"
            "    输入 yes 执行 / abort 中止："
        )
        answer = text.strip().lower()
        if answer == ABORT_WORD:
            self.abort()
            return False
        if answer in GENERIC_YES:
            self._log_confirm("l2_action", text)
            return True
        return False

    def abort(self) -> None:
        """立即退回 L0（HARD：中止不可撤销，需重新走完整门控）。"""
        self._aborted = True
        self._unlocked = False
        self._l2_next_step = 1
        self._level = 0
        audit("gate_abort", {"target": self.target})

    # ---------- 内部 ----------
    def _log_confirm(self, kind: str, text: str) -> None:
        if kind == "l2_step1":
            self._l2_next_step = 2
        elif kind == "l2_step2":
            self._l2_next_step = 3
        elif kind == "l2_step3":
            self._l2_next_step = 1
        self.confirm_log.append({"kind": kind, "text": text.strip(), "ts": time.time()})
        audit("gate_confirm", {"kind": kind, "target": self.target})

    async def _ask(self, prompt: str) -> str:
        return await self._prompt_fn(prompt)

    @staticmethod
    async def _interactive_prompt(prompt: str) -> str:
        """交互确认；stdin 关闭/EOF → 返回空串（门控按未确认处理，流程优雅降级不崩溃）。"""
        try:
            return await asyncio.to_thread(input, prompt)
        except (EOFError, OSError):
            return ""
