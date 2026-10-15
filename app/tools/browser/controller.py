"""Policy-enforced browser/computer-use controller boundary.

A real browser driver (Playwright, WebDriver, native computer-use provider,
etc.) is injected by the caller. The controller itself never creates a driver
from untrusted model input.
"""

from __future__ import annotations

import inspect
from typing import Any, Protocol

from app.tools.browser.policy import BrowserPolicy


class BrowserUnavailableError(RuntimeError):
    """Raised when no approved browser driver is attached."""


class BrowserDriver(Protocol):
    async def navigate(self, url: str) -> Any: ...
    async def click(self, selector: str) -> Any: ...
    async def type_text(self, selector: str, text: str) -> Any: ...


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class BrowserController:
    def __init__(self, policy: BrowserPolicy, driver: BrowserDriver | None = None) -> None:
        self.policy = policy
        self.driver = driver

    def attach(self, driver: BrowserDriver) -> None:
        self.driver = driver

    def _require_driver(self) -> BrowserDriver:
        if self.driver is None:
            raise BrowserUnavailableError("browser driver is not attached")
        return self.driver

    async def navigate(self, url: str) -> Any:
        decision = self.policy.authorize_navigation(url)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        driver = self._require_driver()
        return await _maybe_await(driver.navigate(decision.normalized_url or url))

    async def click(self, selector: str) -> Any:
        if not selector or len(selector) > 500:
            raise ValueError("invalid selector")
        driver = self._require_driver()
        return await _maybe_await(driver.click(selector))

    async def type_text(self, selector: str, text: str, *, contains_secret: bool = False) -> Any:
        if contains_secret and not self.policy.allow_secret_entry:
            raise PermissionError("secret_entry_disabled")
        if not selector or len(selector) > 500:
            raise ValueError("invalid selector")
        if len(text) > 100_000:
            raise ValueError("text payload too large")
        driver = self._require_driver()
        return await _maybe_await(driver.type_text(selector, text))

    def authorize_download(self) -> None:
        decision = self.policy.authorize_download()
        if not decision.allowed:
            raise PermissionError(decision.reason)

    def authorize_upload(self) -> None:
        decision = self.policy.authorize_upload()
        if not decision.allowed:
            raise PermissionError(decision.reason)
