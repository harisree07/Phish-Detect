import os
import asyncio
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger("phish_detect.screenshot")

class ScreenshotManager:
    """
    Leverages Playwright to automate headless browser captures of active websites.
    Saves screenshot PNG files for security investigation.
    """
    
    def __init__(self, output_dir: str = "output", timeout: int = 10):
        self.output_dir = Path(output_dir) / "screenshots"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_ms = timeout * 1000
        
    def capture(self, domain: str) -> Optional[str]:
        """
        Runs synchronous wrapper around the async browser execution to capture a page screenshot.
        
        Args:
            domain (str): Domain of the page to capture.
            
        Returns:
            Optional[str]: Relative path to the saved screenshot file, or None if failed.
        """
        try:
            return asyncio.run(self._capture_async(domain))
        except Exception as e:
            logger.error(f"Playwright capture error for {domain}: {e}")
            return None
            
    async def _capture_async(self, domain: str) -> Optional[str]:
        # Import inside the function to avoid importing if not used or if playwright is missing
        from playwright.async_api import async_playwright
        
        target_url = f"https://{domain}"
        filename = f"{domain.replace('.', '_')}.png"
        filepath = self.output_dir / filename
        
        # Resolve path relative to runtime directory
        relative_path = os.path.join("screenshots", filename)
        
        logger.debug(f"Starting browser instance to capture {target_url}")
        
        async with async_playwright() as p:
            browser = None
            try:
                # Launch headless browser (Chromium)
                browser = await p.chromium.launch(headless=True)
                
                # Context with standard user-agent and viewport size
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ignore_https_errors=True # Crucial for self-signed or invalid certs on phishing sites
                )
                
                page = await context.new_page()
                page.set_default_timeout(self.timeout_ms)
                
                # Navigate to the page. Wait until network is idle or domecontentloaded
                try:
                    await page.goto(target_url, wait_until="domcontentloaded")
                except Exception as e:
                    # Fallback to HTTP if HTTPS fails
                    logger.debug(f"HTTPS screenshot failed for {domain}, trying HTTP: {e}")
                    await page.goto(f"http://{domain}", wait_until="domcontentloaded")
                    
                # Brief sleep to allow dynamic assets to render
                await asyncio.sleep(1)
                
                # Take screenshot
                await page.screenshot(path=filepath, full_page=False)
                logger.info(f"Screenshot successfully saved for {domain} at {filepath}")
                return relative_path
                
            except Exception as e:
                logger.debug(f"Headless browser failed to capture screenshot for {domain}: {e}")
                return None
            finally:
                if browser:
                    await browser.close()
