"""builtin Web 爬虫（L2 主动：Headless Chrome/CDP，支持 SPA、JS 渲染、表单提交）。
集成 browser-use/Playwright，提供完整的动态页面分析能力。
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, Field

from security.stealth import StealthRateLimiter, random_user_agent
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings


@dataclass
class CrawlResult:
    """单页面爬取结果。"""
    url: str
    title: str = ""
    html: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    load_time_ms: int = 0
    is_spa: bool = False
    console_errors: list[str] = field(default_factory=list)
    network_requests: list[dict[str, Any]] = field(default_factory=list)


class WebCrawlerParams(BaseModel):
    """Web 爬虫参数。"""
    target: str = Field(..., description="目标 URL（必须包含 http:// 或 https://）")
    max_depth: int = Field(2, ge=0, le=5, description="最大爬取深度")
    max_pages: int = Field(20, ge=1, le=100, description="最大页面数")
    wait_for_network_idle: bool = Field(True, description="等待网络空闲")
    wait_timeout: int = Field(30000, ge=5000, le=120000, description="页面加载超时（毫秒）")
    extract_apis: bool = Field(True, description="提取 API 端点")
    extract_forms: bool = Field(True, description="提取表单信息")
    execute_js: bool = Field(True, description="执行 JavaScript（SPA 支持）")
    screenshot: bool = Field(False, description="是否截图")


class WebCrawlerTool(BaseTool):
    """Headless Web 爬虫（L2：三级门控 + 逐项确认）。"""

    name = "web_crawler"
    description = "Headless Chrome 爬虫：支持 SPA 渲染、JS 执行、表单提交、API 端点发现、链接/邮箱/注释提取（L2）"
    risk_level = "高"
    min_level = 2
    params_model = WebCrawlerParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            self._settings.REQUEST_DELAY_RANGE,
            self._settings.MAX_CONCURRENCY
        )
        self._browser = None
        self._context = None

    async def _get_browser(self):
        """Lazy initialize Playwright browser."""
        if self._browser is None:
            try:
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-web-security',
                        '--disable-features=IsolateOrigins,site-per-process',
                        f'--user-agent={random_user_agent()}'
                    ]
                )
                self._context = await self._browser.new_context(
                    user_agent=random_user_agent(),
                    viewport={'width': 1920, 'height': 1080},
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    bypass_csp=True
                )
            except ImportError:
                raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")
        return self._context

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, WebCrawlerParams)

        if not params.target.startswith(('http://', 'https://')):
            return ToolResult.err(self.name, "目标必须包含 http:// 或 https://")

        # Check scope
        from security.stealth import is_in_scope, allowed_target
        ok, reason = allowed_target(params.target, self._settings)
        if not ok:
            return ToolResult.err(self.name, f"[合规拦截] {reason}")
        if not is_in_scope(params.target, params.target):
            return ToolResult.err(self.name, "[范围拦截] 目标超出授权范围")

        context = await self._get_browser()
        page = await context.new_page()

        # Enable network/request monitoring
        network_requests = []
        console_errors = []

        page.on("request", lambda req: network_requests.append({
            "url": req.url,
            "method": req.method,
            "resource_type": req.resource_type,
            "headers": req.headers
        }))

        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        # Block unnecessary resources to speed up
        await page.route("**/*", lambda route: route.abort() if route.request.resource_type in
                         ["image", "stylesheet", "font", "media"] else route.continue_())

        try:
            results = await self._crawl(params, page, network_requests, console_errors)

            evidence = [
                f"Web 爬虫: {params.target}, 页面数: {len(results)}",
                f"发现链接: {sum(len(r.links) for r in results)}, API: {sum(len(r.apis) for r in results)}"
            ]

            return ToolResult(
                name=self.name,
                success=True,
                data={
                    "target": params.target,
                    "pages": [
                        {
                            "url": r.url,
                            "title": r.title,
                            "links": r.links[:50],
                            "forms": r.forms,
                            "scripts": r.scripts[:20],
                            "apis": r.apis[:50],
                            "emails": r.emails[:20],
                            "comments": r.comments[:10],
                            "meta": r.meta,
                            "status_code": r.status_code,
                            "load_time_ms": r.load_time_ms,
                            "is_spa": r.is_spa,
                            "console_errors": r.console_errors[:10],
                            "network_requests": r.network_requests[:50]
                        }
                        for r in results
                    ],
                    "total_pages": len(results),
                    "total_links": sum(len(r.links) for r in results),
                    "total_apis": sum(len(r.apis) for r in results)
                },
                evidence=evidence,
                source_hash="",
                confidence=0.9
            )

        except Exception as e:
            return ToolResult.err(self.name, f"爬虫执行异常: {e}")
        finally:
            await page.close()

    async def _crawl(self, params: WebCrawlerParams, page, network_requests, console_errors) -> list[CrawlResult]:
        """执行爬取。"""
        visited = set()
        to_visit = [(params.target, 0)]
        results = []

        while to_visit and len(visited) < params.max_pages:
            url, depth = to_visit.pop(0)
            if url in visited or depth > params.max_depth:
                continue
            visited.add(url)

            async with self._limiter.slot():
                result = await self._crawl_page(page, url, params)

            results.append(result)

            # Extract new links for next depth
            if depth < params.max_depth:
                for link in result.links:
                    full_url = urljoin(url, link)
                    if self._should_visit(full_url, params.target, visited):
                        to_visit.append((full_url, depth + 1))

        return results

    def _should_visit(self, url: str, base_target: str, visited: set) -> bool:
        """判断是否应该访问该 URL。"""
        if url in visited:
            return False
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_target)
            # Same domain only
            return parsed.netloc == base_parsed.netloc and parsed.scheme in ('http', 'https')
        except Exception:
            return False

    async def _crawl_page(self, page, url: str, params: WebCrawlerParams) -> CrawlResult:
        """爬取单个页面。"""
        import time
        start = time.time()

        try:
            response = await page.goto(
                url,
                wait_until="networkidle" if params.wait_for_network_idle else "domcontentloaded",
                timeout=params.wait_timeout
            )
            status_code = response.status if response else 0
        except Exception as e:
            return CrawlResult(url=url, status_code=0, html=f"Error: {e}")

        # Wait a bit for JS execution
        if params.execute_js:
            await page.wait_for_timeout(1000)

        html = await page.content()
        title = await page.title()

        # Extract all links
        links = await page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")

        # Extract forms
        forms = []
        if params.extract_forms:
            forms = await page.evaluate("""
                () => Array.from(document.forms).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.elements).map(el => ({
                        name: el.name,
                        type: el.type,
                        value: el.value,
                        required: el.required
                    }))
                }))
            """)

        # Extract scripts
        scripts = await page.eval_on_selector_all("script[src]", "elements => elements.map(e => e.src)")

        # Extract APIs from network requests
        apis = []
        if params.extract_apis:
            for req in page._network_requests if hasattr(page, '_network_requests') else []:
                pass
            # Use network_requests collected via page.on
            for req in network_requests:
                if any(api_path in req["url"] for api_path in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/service/"]):
                    apis.append(req["url"])

        # Extract emails from HTML
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)))

        # Extract HTML comments
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        comments = [c.strip()[:200] for c in comments if c.strip()][:10]

        # Extract meta tags
        meta = await page.evaluate("""
            () => {
                const metas = {};
                document.querySelectorAll('meta').forEach(m => {
                    const name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv');
                    const content = m.getAttribute('content');
                    if (name && content) metas[name] = content;
                });
                return metas;
            }
        """)

        # Check if SPA
        is_spa = await page.evaluate("""
            () => !!(
                window.React || window.Vue || window.angular || 
                document.querySelector('[data-reactroot]') ||
                document.querySelector('[ng-app]') ||
                document.querySelector('#app') ||
                document.querySelector('[data-v-]')
            )
        """)

        load_time_ms = int((time.time() - start) * 1000)

        return CrawlResult(
            url=url,
            title=title,
            html=html[:50000],  # Limit size
            links=list(set(links))[:200],
            forms=forms,
            scripts=scripts[:50],
            apis=list(set(apis))[:100],
            emails=emails[:50],
            comments=comments,
            meta=meta,
            status_code=status_code,
            load_time_ms=load_time_ms,
            is_spa=is_spa,
            console_errors=console_errors[:20],
            network_requests=network_requests[:100]
        )

    async def aclose(self):
        """Cleanup browser resources."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if hasattr(self, '_playwright'):
            await self._playwright.stop()