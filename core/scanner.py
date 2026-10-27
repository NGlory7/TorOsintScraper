import asyncio
import os
import re
from playwright.async_api import async_playwright, TimeoutError
from .network import TorManager
from .analyzer import analyze_content

class OSINTScanner:
    def __init__(self, targets: list[str], tor_manager: TorManager | None = None, concurrency: int = 3, timeout_sec: int = 90, use_proxy: bool = True):
        self.targets = targets
        self.tor = tor_manager or TorManager()
        self.concurrency = concurrency
        self.timeout_ms = timeout_sec * 1000
        self.use_proxy = use_proxy
        self.results: list[dict] = []
        self.screenshots_path = ""

    def normalize_url(self, raw_url: str) -> str:
        """URL'nin başında http/https protokolü yoksa http:// ekler."""
        raw_url = raw_url.strip()
        if not raw_url.startswith(("http://", "https://")):
            return f"http://{raw_url}"
        return raw_url

    async def scan_single_target(self, browser, url: str, sem: asyncio.Semaphore) -> dict:
        async with sem:
            url = self.normalize_url(url)
            print(f"[*] İşleniyor: {url}")

            # .onion çözünürlüğü için hem context hem browser proxy ayarı şart
            proxy_cfg = {"server": self.tor.proxy_addr} if (self.use_proxy and self.tor.proxy_addr) else None

            context = await browser.new_context(
                proxy=proxy_cfg,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
            )
            page = await context.new_page()

            # Orijinal dosya adı sanitizasyonu
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url.replace("http://", "").replace("https://", ""))[:50]
            screenshot_file = f"{safe_name}.png"
            full_ss_path = os.path.join(self.screenshots_path, screenshot_file)

            try:
                # Tor ağında siteler yavaş açılabilir, varsayılan süre 90 saniye
                await page.goto(url, wait_until="load", timeout=self.timeout_ms)

                # Ekran görüntüsü al (tam sayfa, zaman aşımı korumalı)
                try:
                    await page.screenshot(path=full_ss_path, full_page=True, timeout=15000)
                except Exception:
                    await page.screenshot(path=full_ss_path, full_page=False)

                html = await page.content()
                analysis = analyze_content(html)

                return {
                    "url": url,
                    "status": "Up",
                    "screenshot": screenshot_file,
                    "analysis": analysis
                }

            except TimeoutError:
                print(f"    [-] {url} zaman aşımına uğradı ({self.timeout_ms // 1000}s).")
                return {"url": url, "status": "Down", "error": f"Timeout ({self.timeout_ms // 1000}s)"}
            except Exception as e:
                err_msg = str(e).split("\n")[0]
                print(f"    [-] {url} bağlantı hatası: {err_msg}")
                return {"url": url, "status": "Down", "error": err_msg}
            finally:
                await page.close()
                await context.close()

    async def run(self, session_folder: str) -> list[dict]:
        self.screenshots_path = os.path.join(session_folder, "screenshots")
        os.makedirs(self.screenshots_path, exist_ok=True)

        # SOCKS5 Proxy ve DNS yönlendirme ayarları
        if self.use_proxy and self.tor.proxy_addr:
            proxy_args = [
                f"--proxy-server={self.tor.proxy_addr}",
                "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
                "--ignore-certificate-errors",
                "--no-sandbox",
                "--disable-dev-shm-usage"
            ]
        else:
            proxy_args = [
                "--no-sandbox",
                "--disable-dev-shm-usage"
            ]

        semaphore = asyncio.Semaphore(self.concurrency)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=proxy_args
            )

            tasks = [self.scan_single_target(browser, url, semaphore) for url in self.targets]
            self.results = await asyncio.gather(*tasks)

            await browser.close()

        return self.results
