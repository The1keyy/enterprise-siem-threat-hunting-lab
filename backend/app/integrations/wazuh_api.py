"""Async client for the Wazuh manager API.

VERIFY (4.14.9):
- Base URL https://<WAZUH_MANAGER_IP>:55000
- POST /security/user/authenticate with HTTP Basic auth
- JWT in data.token, lifetime about 900s, no expires_in field
- Authorization: Bearer <token>
- GET /agents, GET /manager/status, GET /manager/info, GET /rules
- Pagination query names limit and offset, and total_affected_items
- Rule objects use filename and status
"""

import base64
import json
import time
from collections.abc import Callable
from typing import Any

import httpx

from app.core.config import Settings
from app.integrations.errors import WazuhAuthError, WazuhResponseError, WazuhUnavailable
from app.integrations.tls import tls_verify

# VERIFY (4.14.9): these paths and the affected_items envelope.
_AUTH_PATH = "/security/user/authenticate"
_AGENTS_PATH = "/agents"
_STATUS_PATH = "/manager/status"
_INFO_PATH = "/manager/info"
_RULES_PATH = "/rules"
_PAGE_LIMIT = 500
_MAX_PAGES = 20


def _jwt_exp(token: str) -> float | None:
    """Read exp without verifying the signature. It is only a cache hint."""

    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + padding))
    except (ValueError, json.JSONDecodeError):
        return None
    exp = data.get("exp") if isinstance(data, dict) else None
    if isinstance(exp, (int, float)):
        return float(exp)
    return None


def _items(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int | None]:
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("affected_items"), list):
        raise WazuhResponseError("Wazuh API response missing affected_items")
    items = [item for item in data["affected_items"] if isinstance(item, dict)]
    total = data.get("total_affected_items")
    return items, total if isinstance(total, int) else None


class WazuhApiClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings
        self._clock = clock or time.time
        self._token: str | None = None
        self._expires_at = 0.0
        self._client = httpx.AsyncClient(
            base_url=settings.wazuh_api_url.rstrip("/"),
            timeout=settings.wazuh_timeout_seconds,
            verify=tls_verify(settings),
            transport=transport,
            trust_env=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _token_is_fresh(self) -> bool:
        if not self._token:
            return False
        skew = self._settings.wazuh_token_refresh_skew_seconds
        return self._clock() < self._expires_at - skew

    def _remember(self, token: str) -> None:
        self._token = token
        exp = _jwt_exp(token)
        if exp is None:
            # VERIFY (4.14.9): default auth token lifetime is about 900 seconds.
            exp = self._clock() + self._settings.wazuh_token_ttl_seconds
        self._expires_at = exp

    async def _authenticate(self) -> None:
        try:
            response = await self._client.post(
                _AUTH_PATH,
                auth=(self._settings.wazuh_api_user, self._settings.wazuh_api_password),
            )
        except httpx.HTTPError as exc:
            raise WazuhUnavailable("Wazuh manager API unreachable") from exc
        if response.status_code in {401, 403}:
            raise WazuhAuthError("Wazuh API authentication failed")
        if response.status_code >= 500:
            raise WazuhUnavailable(f"Wazuh manager API returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise WazuhResponseError(f"Wazuh manager API returned HTTP {response.status_code}")
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise WazuhResponseError("Wazuh API authentication response was not JSON") from exc
        token = body.get("data", {}).get("token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise WazuhAuthError("Wazuh API authentication response missing data.token")
        self._remember(token)

    async def _ensure_token(self) -> None:
        if not self._token_is_fresh():
            await self._authenticate()

    async def _request(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        await self._ensure_token()
        response = await self._send(path, params=params)
        if response.status_code == 401:
            self._token = None
            self._expires_at = 0.0
            await self._authenticate()
            response = await self._send(path, params=params)
            if response.status_code == 401:
                raise WazuhAuthError("Wazuh API rejected the refreshed token")
        if response.status_code >= 500:
            raise WazuhUnavailable(f"Wazuh manager API returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise WazuhResponseError(f"Wazuh manager API returned HTTP {response.status_code}")
        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise WazuhResponseError("Wazuh API response was not JSON") from exc
        if not isinstance(body, dict):
            raise WazuhResponseError("Wazuh API response was not an object")
        return body

    async def _send(self, path: str, *, params: dict[str, Any] | None) -> httpx.Response:
        try:
            return await self._client.get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise WazuhUnavailable("Wazuh manager API unreachable") from exc

    async def _collect(self, path: str) -> list[dict[str, Any]]:
        # VERIFY (4.14.9): limit/offset pagination. Filename filtering is done here
        # so a wrong server-side filter cannot hide custom rules.
        collected: list[dict[str, Any]] = []
        offset = 0
        for _ in range(_MAX_PAGES):
            payload = await self._request(path, params={"limit": _PAGE_LIMIT, "offset": offset})
            items, total = _items(payload)
            collected.extend(items)
            offset += len(items)
            if not items or (total is not None and offset >= total):
                break
        return collected

    async def get_agents(self) -> list[dict[str, Any]]:
        return await self._collect(_AGENTS_PATH)

    async def get_manager_status(self) -> dict[str, Any]:
        items, _total = _items(await self._request(_STATUS_PATH))
        if not items:
            raise WazuhResponseError("Wazuh manager status response was empty")
        return items[0]

    async def get_manager_info(self) -> dict[str, Any]:
        items, _total = _items(await self._request(_INFO_PATH))
        if not items:
            raise WazuhResponseError("Wazuh manager info response was empty")
        return items[0]

    async def get_custom_rules(self) -> list[dict[str, Any]]:
        rules = await self._collect(_RULES_PATH)
        custom: list[dict[str, Any]] = []
        for rule in rules:
            filename = rule.get("filename")
            if isinstance(filename, str) and filename.startswith("sentinelforge"):
                custom.append(rule)
        return custom
