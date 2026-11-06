"""builtin L3 云存储枚举：bucket 候选 × OSS/S3/COS 单次只读 GET 分类。

HARD：全部请求打云厂商端点（非目标基础设施，扰动=0）；bucket 候选 ≤
CLOUD_BUCKET_CAP；不列举对象内容、不写入、不删除——仅判定桶存在性与可读性。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

# 平台 → URL 模板（区域默认值显式声明为 [区域猜测]，命中后建议人工核实其余区域）
PLATFORMS: dict[str, str] = {
    "oss": "https://{bucket}.oss-cn-hangzhou.aliyuncs.com/",
    "s3": "https://{bucket}.s3.amazonaws.com/",
    "cos": "https://{bucket}.cos.ap-guangzhou.myqcloud.com/",
    "azure": "https://{bucket}.blob.core.windows.net/",
    "gcs": "https://{bucket}.storage.googleapis.com/",
    "obs": "https://{bucket}.obs.cn-north-4.myhuaweicloud.com/",
}


def bucket_candidates(domain: str, cap: int, subdomains: list[str] | None = None) -> list[str]:
    """纯函数：主域（+已发现子域）→ bucket 命名候选（≤cap，去重）。"""
    name = domain.split(".")[0].lower().replace("-", "")
    tld = ".".join(domain.split(".")[-2:]).replace(".", "-")
    # 子域派生：api.example.com → api / api-static / api-assets（子域常直连桶）
    sub_names = [s.split(".")[0].lower() for s in (subdomains or [])[:20]]
    templates = tuple(dict.fromkeys(
        [n for n in sub_names if n]
        + [f"{n}-static" for n in sub_names if n]
        + [f"{n}-assets" for n in sub_names if n]))
    templates += (
        name, f"{name}-backup", f"{name}-backups", f"{name}-static", f"{name}-assets",
        f"{name}-img", f"{name}-images", f"{name}-log", f"{name}-logs", f"{name}-data",
        f"{name}-dev", f"{name}-test", f"{name}-prod", f"{name}-public", f"{name}-files",
        f"{name}-download", f"{name}-media", f"{name}-video", f"{name}-doc", f"{name}-db",
        f"{name}-app", f"{name}-web", f"{name}-tmp", f"{name}-temp",
        domain.replace(".", "-"), tld, f"{tld}-static", f"{tld}-backup",
    )
    out: list[str] = []
    for cand in templates:
        if cand and cand not in out:
            out.append(cand)
        if len(out) >= cap:
            break
    return out[:cap]


def classify_bucket_response(status: int, body: str) -> dict:
    """纯函数：单次 GET 响应 → 存在性/可读性判定（S3/OSS/COS/Azure/GCS/OBS 统一）。"""
    text = (body or "")[:4000]
    if status == 200 and ("ListBucketResult" in text or "<Blobs>" in text
                          or "ListBucketResult" in text or "ListAllMyBucketsResult" in text):
        return {"verdict": "public_list", "severity": "High",
                "note": "桶可匿名列举（ListBucketResult/Blobs）— 高危发现，人工核实"}
    if status == 200:
        return {"verdict": "public_read", "severity": "Medium",
                "note": "桶可匿名读取（未见列举接口）"}
    if status == 403:
        return {"verdict": "exists_denied", "severity": "Low",
                "note": "桶存在但拒绝匿名访问（配置正确）"}
    if status in (404, 400) or any(m in text for m in
                                   ("NoSuchBucket", "BlobNotFound", "ContainerNotFound",
                                    "NoSuchKey")):
        return {"verdict": "absent", "severity": "Info", "note": "桶不存在"}
    return {"verdict": "unknown", "severity": "Info", "note": f"HTTP {status}"}


class CloudEnumParams(BaseModel):
    """云存储枚举参数。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="授权主域名")
    platforms: list[str] = Field(
        default_factory=lambda: ["oss", "s3", "cos", "azure", "gcs", "obs"],
        description="平台列表（子集）")
    subdomains: list[str] = Field(default_factory=list, max_length=100,
                                  description="已发现子域（派生桶名候选）")


class CloudEnumTool(BaseTool):
    """L3 云存储 bucket 枚举（只读单 GET/候选/平台）。"""

    name = "cloud_enum"
    description = "云存储枚举：OSS/S3/COS bucket 命名候选单次 GET 分类（可匿名列举=High，零目标接触）"
    risk_level = "中"
    min_level = 3
    params_model = CloudEnumParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, CloudEnumParams)
        domain = params.target.lower().rstrip(".")
        platforms = [p for p in params.platforms if p in PLATFORMS]
        buckets = bucket_candidates(domain, self._settings.CLOUD_BUCKET_CAP,
                                    params.subdomains)  # HARD cap
        notes: list[str] = ["OSS/COS/OBS/Azure 按默认区域探测，命中后建议人工核实其余区域"]

        sem = asyncio.Semaphore(3)

        async def probe(bucket: str, platform: str) -> dict | None:
            url = PLATFORMS[platform].format(bucket=bucket)
            async with sem:
                try:
                    status, _, body = await run_sync(
                        http_get, url, self._settings.CONNECT_TIMEOUT, False, 20_000)
                except (OSError, ValueError):
                    return None
            verdict = classify_bucket_response(status, body)
            if verdict["verdict"] in ("absent", "unknown"):
                return None
            return {"bucket": bucket, "platform": platform, "url": url,
                    "http": status, **verdict}

        tasks = [probe(b, p) for b in buckets for p in platforms]
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        findings = [r for r in raw if isinstance(r, dict)]

        data = {
            "target": domain, "buckets_tried": len(buckets),
            "platforms": platforms, "requests": len(tasks),
            "findings": findings,
            "notes": notes,
        }
        high = sum(1 for f in findings if f.get("severity") == "High")
        return ToolResult(
            name=self.name,
            success=True,
            data=data,
            evidence=[f"云存储枚举: {len(buckets)} 候选 × {len(platforms)} 平台 = {len(tasks)} 次 GET"
                      f"（全部打云厂商端点，零目标接触）",
                      f"发现 {len(findings)} 个桶（High {high}）；不列举对象、不写入（HARD）"],
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.75 if findings else 0.5,
        )
