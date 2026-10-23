"""CVE 快照构建：从 OSV 拉取常见产品漏洞 → 写快照 + SHA256 签名（防投毒，HARD）。

用法：python -m knowledge.snapshot [产品1 产品2 ...]
每个产品自动匹配 OSV ecosystem（name + ecosystem 联合查询）。
快照构建后自动校验：空快照显式报错而非静默写入。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

from platforms.paths import get_cve_dir
from utils.config import get_settings
from utils.logger import err, info, ok, warn

OSV_API = "https://api.osv.dev/v1/query"

# 产品 → OSV ecosystem 映射（ecosystem 必须与 OSV 注册名一致，否则 400）
PRODUCT_ECOSYSTEM: dict[str, str] = {
    "wordpress": "Packagist", "drupal": "Packagist", "laravel": "Packagist",
    "django": "PyPI", "flask": "PyPI", "fastapi": "PyPI",
    "jquery": "npm", "vue": "npm", "react": "npm", "lodash": "npm",
    "tomcat": "Maven", "spring": "Maven", "struts": "Maven",
    "nginx": "alpine", "apache": "alpine", "openssl": "alpine",
}
DEFAULT_PRODUCTS = list(PRODUCT_ECOSYSTEM.keys())
MAX_PER_PRODUCT = 50  # 每产品最多拉取漏洞数


def _query_osv(product: str, ecosystem: str, timeout: int) -> list[dict]:
    """同步 OSV 查询（name + ecosystem 联合）。"""
    body = json.dumps({
        "package": {"name": product, "ecosystem": ecosystem},
    }).encode("utf-8")
    req = urllib.request.Request(
        OSV_API, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return [
        {"id": v.get("id"),
         "summary": (v.get("summary") or "")[:160],
         "aliases": v.get("aliases", [])[:5],
         "severity": next(
             (s.get("score") for s in v.get("severity", [])
              if s.get("type") == "CVSS_V3"), ""),
         "affected": [
             a["package"]["name"] for a in v.get("affected", [])
             if a.get("package", {}).get("name")
         ][:3],
         }
        for v in data.get("vulns", [])
    ][:MAX_PER_PRODUCT]


async def build_snapshot(product_names: list[str], out_dir: Path | None = None) -> Path:
    """构建签名快照；空快照显式报错（HARD）。"""
    settings = get_settings()
    out_dir = out_dir or get_cve_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    entries: dict = {}
    total = 0
    failed: list[str] = []

    for name in product_names:
        eco = PRODUCT_ECOSYSTEM.get(name.lower(), "PyPI")
        try:
            vulns = await asyncio.to_thread(_query_osv, name, eco, settings.CONNECT_TIMEOUT * 3)
            entries[name.lower()] = {"ecosystem": eco, "vulns": vulns}
            total += len(vulns)
            info(f"OSV: {name} ({eco}) 拉取 {len(vulns)} 条")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            failed.append(name)
            entries[name.lower()] = {"vulns": [], "error": str(exc)[:160]}
            warn(f"OSV: {name} 拉取失败（{type(exc).__name__}）")

    payload = {
        "snapshot_date": time.strftime("%Y-%m-%d"),
        "source": "OSV(api.osv.dev)",
        "total_vulns": total,
        "total_products": len(entries),
        "failed_products": failed,
        "entries": entries,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    snapshot_path = out_dir / "snapshot.json"
    sig_path = out_dir / "snapshot.sig"
    snapshot_path.write_bytes(raw)
    sig_path.write_text(hashlib.sha256(raw).hexdigest(), encoding="utf-8", newline="")

    if total > 0:
        ok(f"快照已写入 {snapshot_path}（{total} 条漏洞 / {len(entries)} 产品）")
    else:
        err(f"[快照为空] {len(entries)} 产品 0 条漏洞——检查 ecosystem 映射或网络连通性")
    return snapshot_path


def main(argv: list[str]) -> int:
    """CLI 入口：python -m knowledge.snapshot [产品1 产品2 ...]。"""
    names = list(argv[1:]) or DEFAULT_PRODUCTS
    try:
        asyncio.run(build_snapshot(names))
        return 0
    except OSError as exc:
        err(f"快照构建失败（离线?）: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
