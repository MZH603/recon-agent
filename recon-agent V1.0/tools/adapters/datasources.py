"""Unified data source adapters for external intelligence APIs.
Supports: FOFA, Quake, ZoomEye, 微步在线, ThreatBook, Shodan, Censys, BinaryEdge.
All adapters share a common interface and respect rate limits.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, urlencode

from platforms.sync_worker import run_sync
import aiohttp

from utils.config import Settings, get_settings
from security.stealth import StealthRateLimiter, random_user_agent


@dataclass
class DataSourceResult:
    """Standardized result from a data source query."""
    source: str
    query: str
    assets: list[dict[str, Any]]  # Each asset: {type, value, metadata...}
    raw_response: dict
    success: bool
    error: str = ""
    rate_limited: bool = False


class DataSourceAdapter(ABC):
    """Base class for all data source adapters."""

    def __init__(self, settings: Settings, api_key: str = "", api_secret: str = ""):
        self.settings = settings
        self.api_key = api_key
        self.api_secret = api_secret
        self._limiter = StealthRateLimiter(
            getattr(settings, f"{self.name.upper()}_DELAY_RANGE", (3.0, 10.0)),
            getattr(settings, f"{self.name.upper()}_MAX_CONCURRENCY", 1)
        )
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this data source."""
        pass

    @property
    @abstractmethod
    def base_url(self) -> str:
        """Base API URL."""
        pass

    @abstractmethod
    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        """Build (url, headers, params) for the API request."""
        pass

    @abstractmethod
    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        """Parse API response into standardized asset list."""
        pass

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.settings.CONNECT_TIMEOUT)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def query(self, query: str, page: int = 1, size: int = 100) -> DataSourceResult:
        """Execute a query against the data source."""
        if not self.api_key:
            return DataSourceResult(
                source=self.name, query=query, assets=[], raw_response={},
                success=False, error="API key not configured"
            )

        url, headers, params = self._build_request(query, page, size)

        async with self._limiter.slot():
            session = await self._get_session()
            try:
                async with session.get(url, headers=headers, params=params) as resp:
                    raw = await resp.json()
                    if resp.status == 429:
                        return DataSourceResult(
                            source=self.name, query=query, assets=[], raw_response=raw,
                            success=False, error="Rate limited", rate_limited=True
                        )
                    if resp.status != 200:
                        return DataSourceResult(
                            source=self.name, query=query, assets=[], raw_response=raw,
                            success=False, error=f"HTTP {resp.status}: {raw.get('message', 'Unknown error')}"
                        )
                    assets = self._parse_response(raw, query)
                    return DataSourceResult(
                        source=self.name, query=query, assets=assets,
                        raw_response=raw, success=True
                    )
            except aiohttp.ClientError as e:
                return DataSourceResult(
                    source=self.name, query=query, assets=[], raw_response={},
                    success=False, error=f"Network error: {e}"
                )
            except json.JSONDecodeError:
                return DataSourceResult(
                    source=self.name, query=query, assets=[], raw_response={},
                    success=False, error="Invalid JSON response"
                )


class FOFAAdapter(DataSourceAdapter):
    """FOFA API adapter (fofa.info)."""

    @property
    def name(self) -> str:
        return "fofa"

    @property
    def base_url(self) -> str:
        return "https://fofa.info/api/v1"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        # FOFA requires base64 encoded query
        qbase64 = base64.b64encode(query.encode()).decode()
        params = {
            "key": self.api_key,
            "qbase64": qbase64,
            "page": page,
            "size": min(size, 10000),  # FOFA max
            "fields": "host,ip,port,protocol,title,header,body,cert,server,city,country,asn,org"
        }
        return f"{self.base_url}/search/all", {"User-Agent": random_user_agent()}, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if data.get("error"):
            return []
        assets = []
        for item in data.get("results", []):
            if len(item) >= 10:
                assets.append({
                    "type": "host",
                    "value": item[0],  # host
                    "ip": item[1],
                    "port": item[2],
                    "protocol": item[3],
                    "title": item[4],
                    "header": item[5],
                    "body": item[6][:500] if item[6] else "",
                    "cert": item[7],
                    "server": item[8],
                    "city": item[9],
                    "country": item[10],
                    "asn": item[11] if len(item) > 11 else "",
                    "org": item[12] if len(item) > 12 else "",
                    "source": "fofa",
                    "query": query
                })
        return assets


class QuakeAdapter(DataSourceAdapter):
    """Quake API adapter (quake.360.net)."""

    @property
    def name(self) -> str:
        return "quake"

    @property
    def base_url(self) -> str:
        return "https://quake.360.net/api/v3"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        headers = {
            "X-QuakeToken": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": random_user_agent()
        }
        payload = {
            "query": query,
            "start": (page - 1) * size,
            "size": min(size, 100),
            "ignore_cache": False
        }
        return f"{self.base_url}/search/quake_service", headers, payload

    async def query(self, query: str, page: int = 1, size: int = 100) -> DataSourceResult:
        if not self.api_key:
            return DataSourceResult(
                source=self.name, query=query, assets=[], raw_response={},
                success=False, error="API key not configured"
            )

        url, headers, payload = self._build_request(query, page, size)

        async with self._limiter.slot():
            session = await self._get_session()
            try:
                async with session.post(url, headers=headers, json=payload) as resp:
                    raw = await resp.json()
                    if resp.status == 429:
                        return DataSourceResult(
                            source=self.name, query=query, assets=[], raw_response=raw,
                            success=False, error="Rate limited", rate_limited=True
                        )
                    if resp.status != 200:
                        return DataSourceResult(
                            source=self.name, query=query, assets=[], raw_response=raw,
                            success=False, error=f"HTTP {resp.status}"
                        )
                    assets = self._parse_response(raw, query)
                    return DataSourceResult(
                        source=self.name, query=query, assets=assets,
                        raw_response=raw, success=True
                    )
            except aiohttp.ClientError as e:
                return DataSourceResult(
                    source=self.name, query=query, assets=[], raw_response={},
                    success=False, error=f"Network error: {e}"
                )

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if data.get("code") != 0:
            return []
        assets = []
        for item in data.get("data", []):
            assets.append({
                "type": "host",
                "value": item.get("url", ""),
                "ip": item.get("ip", ""),
                "port": item.get("port", ""),
                "protocol": item.get("service", {}).get("name", ""),
                "title": item.get("service", {}).get("http", {}).get("title", ""),
                "header": str(item.get("service", {}).get("http", {}).get("headers", {})),
                "server": item.get("service", {}).get("http", {}).get("server", ""),
                "location": item.get("location", {}),
                "source": "quake",
                "query": query
            })
        return assets


class ZoomEyeAdapter(DataSourceAdapter):
    """ZoomEye API adapter (zoomeye.org)."""

    @property
    def name(self) -> str:
        return "zoomeye"

    @property
    def base_url(self) -> str:
        return "https://api.zoomeye.org/v2"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        headers = {
            "API-KEY": self.api_key,
            "User-Agent": random_user_agent()
        }
        params = {
            "query": query,
            "page": page,
            "pagesize": min(size, 1000)
        }
        return f"{self.base_url}/search", headers, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if "matches" not in data:
            return []
        assets = []
        for item in data.get("matches", []):
            assets.append({
                "type": "host",
                "value": item.get("ip", ""),
                "ip": item.get("ip", ""),
                "port": item.get("portinfo", {}).get("port", ""),
                "protocol": item.get("portinfo", {}).get("service", ""),
                "title": item.get("portinfo", {}).get("title", ""),
                "header": str(item.get("portinfo", {}).get("banner", "")),
                "country": item.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
                "city": item.get("geoinfo", {}).get("city", {}).get("names", {}).get("en", ""),
                "org": item.get("geoinfo", {}).get("isp", ""),
                "source": "zoomeye",
                "query": query
            })
        return assets


class WeibuAdapter(DataSourceAdapter):
    """微步在线威胁情报 API adapter (threatbook.cn / x.threatbook.cn)."""

    @property
    def name(self) -> str:
        return "weibu"

    @property
    def base_url(self) -> str:
        return "https://x.threatbook.cn/api/v1"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        headers = {"User-Agent": random_user_agent()}
        # Support both IP and domain queries
        params = {
            "apikey": self.api_key,
            "resource": query,
            "field": "summary,malware,related"
        }
        return f"{self.base_url}/ip/reputation", headers, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if data.get("response_code") != 0:
            return []
        assets = []
        # ThreatBook returns single IP reputation, wrap as asset
        if "data" in data and query in data["data"]:
            item = data["data"][query]
            assets.append({
                "type": "ip_reputation",
                "value": query,
                "ip": query,
                "judgments": item.get("judgments", []),
                "tags": item.get("tags", []),
                "malware_families": [m.get("family") for m in item.get("malware", [])],
                "confidence": item.get("confidence", 0),
                "severity": item.get("severity", ""),
                "source": "weibu",
                "query": query
            })
        return assets


class ThreatBookAdapter(DataSourceAdapter):
    """ThreatBook API adapter (api.threatbook.io)."""

    @property
    def name(self) -> str:
        return "threatbook"

    @property
    def base_url(self) -> str:
        return "https://api.threatbook.io/v3"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        headers = {"User-Agent": random_user_agent()}
        params = {
            "apikey": self.api_key,
            "resource": query,
            "lang": "en"
        }
        return f"{self.base_url}/domain/report", headers, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if data.get("response_code") != 0:
            return []
        assets = []
        if "data" in data and query in data["data"]:
            item = data["data"][query]
            # Subdomains
            for sub in item.get("sub_domains", []):
                assets.append({
                    "type": "subdomain",
                    "value": sub,
                    "source": "threatbook",
                    "query": query
                })
            # DNS records
            for record in item.get("dns_records", []):
                assets.append({
                    "type": "dns",
                    "value": record.get("value", ""),
                    "record_type": record.get("type", ""),
                    "source": "threatbook",
                    "query": query
                })
        return assets


class ShodanAdapter(DataSourceAdapter):
    """Shodan API adapter (shodan.io)."""

    @property
    def name(self) -> str:
        return "shodan"

    @property
    def base_url(self) -> str:
        return "https://api.shodan.io/shodan"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        headers = {"User-Agent": random_user_agent()}
        params = {
            "key": self.api_key,
            "query": query,
            "page": page,
            "minify": "true"
        }
        return f"{self.base_url}/host/search", headers, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if "matches" not in data:
            return []
        assets = []
        for item in data.get("matches", []):
            assets.append({
                "type": "host",
                "value": item.get("ip_str", ""),
                "ip": item.get("ip_str", ""),
                "port": item.get("port", ""),
                "protocol": item.get("transport", ""),
                "banner": item.get("data", "")[:1000],
                "org": item.get("org", ""),
                "isp": item.get("isp", ""),
                "location": item.get("location", {}),
                "tags": item.get("tags", []),
                "vulns": list(item.get("vulns", {}).keys()),
                "source": "shodan",
                "query": query
            })
        return assets


class CensysAdapter(DataSourceAdapter):
    """Censys API adapter (search.censys.io)."""

    @property
    def name(self) -> str:
        return "censys"

    @property
    def base_url(self) -> str:
        return "https://search.censys.io/api/v2"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        credentials = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {credentials}",
            "User-Agent": random_user_agent()
        }
        params = {
            "q": query,
            "page": page,
            "per_page": min(size, 100)
        }
        return f"{self.base_url}/hosts/search", headers, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if "result" not in data or "hits" not in data["result"]:
            return []
        assets = []
        for item in data["result"]["hits"]:
            assets.append({
                "type": "host",
                "value": item.get("ip", ""),
                "ip": item.get("ip", ""),
                "services": [
                    {
                        "port": s.get("port"),
                        "service_name": s.get("service_name"),
                        "banner": s.get("banner", "")[:500]
                    }
                    for s in item.get("services", [])
                ],
                "location": item.get("location", {}),
                "source": "censys",
                "query": query
            })
        return assets


class BinaryEdgeAdapter(DataSourceAdapter):
    """BinaryEdge API adapter (api.binaryedge.io)."""

    @property
    def name(self) -> str:
        return "binaryedge"

    @property
    def base_url(self) -> str:
        return "https://api.binaryedge.io/v2"

    def _build_request(self, query: str, page: int, size: int) -> tuple[str, dict, dict]:
        headers = {
            "X-Key": self.api_key,
            "User-Agent": random_user_agent()
        }
        params = {
            "query": query,
            "page": page,
            "pagesize": min(size, 100)
        }
        return f"{self.base_url}/query/search", headers, params

    def _parse_response(self, data: dict, query: str) -> list[dict[str, Any]]:
        if "events" not in data:
            return []
        assets = []
        for item in data.get("events", []):
            assets.append({
                "type": "host",
                "value": item.get("target", {}).get("ip", ""),
                "ip": item.get("target", {}).get("ip", ""),
                "port": item.get("target", {}).get("port", ""),
                "protocol": item.get("result", {}).get("protocol", ""),
                "banner": str(item.get("result", {}).get("data", ""))[:1000],
                "country": item.get("origin", {}).get("country", ""),
                "source": "binaryedge",
                "query": query
            })
        return assets


# Registry of all adapters
ADAPTERS: dict[str, type[DataSourceAdapter]] = {
    "fofa": FOFAAdapter,
    "quake": QuakeAdapter,
    "zoomeye": ZoomEyeAdapter,
    "weibu": WeibuAdapter,
    "threatbook": ThreatBookAdapter,
    "shodan": ShodanAdapter,
    "censys": CensysAdapter,
    "binaryedge": BinaryEdgeAdapter,
}


def get_adapter(name: str, settings: Settings, api_key: str = "", api_secret: str = "") -> DataSourceAdapter:
    """Factory to get adapter instance."""
    adapter_class = ADAPTERS.get(name.lower())
    if not adapter_class:
        raise ValueError(f"Unknown data source: {name}")
    return adapter_class(settings, api_key, api_secret)


async def query_all_sources(
    query: str,
    settings: Settings,
    enabled_sources: list[str],
    api_keys: dict[str, str],
    api_secrets: dict[str, str] = None
) -> list[DataSourceResult]:
    """Query multiple data sources concurrently."""
    api_secrets = api_secrets or {}
    tasks = []
    for source in enabled_sources:
        if source.lower() in ADAPTERS:
            adapter = get_adapter(source, settings, api_keys.get(source, ""), api_secrets.get(source, ""))
            tasks.append(adapter.query(query))
    if not tasks:
        return []
    return await asyncio.gather(*tasks, return_exceptions=False)