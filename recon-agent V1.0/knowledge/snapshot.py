"""CVE 快照构建：从 OSV 拉取常见产品漏洞 → 写快照 + SHA256 签名（防投毒，HARD）。

用法：python -m knowledge.snapshot [产品1 产品2 ...]
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
from utils.logger import err, info, ok

OSV_API = "https://api.osv.dev/v1/query"
DEFAULT_PRODUCTS = ("wordpress", "nginx", "apache", "tomcat", "django", "laravel", "jquery")


def _query_osv(product: str, timeout: int) -> list[dict]:
    """POST OSV 查询单产品漏洞列表（失败抛给上层显式记录）。"""
    body = json.dumps({"package": {"name": product}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_API, data=body, headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return [
        {"id": v.get("id"), "summary": (v.get("summary") or "")[:160],
         "aliases": v.get("aliases", [])[:5]}
        for v in data.get("vulns", [])
    ][:50]


async def build_snapshot(products: list[str], out_dir: Path | None = None) -> Path:
    """构建签名快照；任一产品失败只记警告，不阻塞整体。"""
    settings = get_settings()
    out_dir = out_dir or get_cve_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    entries: dict = {}
    for product in products:
        try:
            vulns = await asyncio.to_thread(_query_osv, product, settings.CONNECT_TIMEOUT * 3)
            entries[product.lower()] = {"vulns": vulns}
            info(f"OSV: {product} 拉取 {len(vulns)} 条")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            entries[product.lower()] = {"vulns": [], "error": str(exc)[:160]}
    payload = {
        "snapshot_date": time.strftime("%Y-%m-%d"),
        "source": "OSV(api.osv.dev)",
        "entries": entries,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    snapshot_path = out_dir / "snapshot.json"
    sig_path = out_dir / "snapshot.sig"
    snapshot_path.write_bytes(raw)
    sig_path.write_text(hashlib.sha256(raw).hexdigest(), encoding="utf-8", newline="")
    ok(f"快照已写入 {snapshot_path}（SHA256 签名 {sig_path.name}）")
    return snapshot_path


def main(argv: list[str]) -> int:
    """CLI 入口。"""
    products = list(argv[1:]) or list(DEFAULT_PRODUCTS)
    try:
        asyncio.run(build_snapshot(products))
        return 0
    except OSError as exc:
        err(f"快照构建失败（离线?）: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
