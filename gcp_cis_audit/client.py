"""Thin read-only GCP REST client built on google-auth.

Only GET (and the POST-style ``getIamPolicy`` calls) are ever issued, so the
audit never modifies the environment.  ``google-auth`` is imported lazily so the
demo mode and unit tests work without it installed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class ApiError(Exception):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.url = url

    @property
    def service_disabled(self) -> bool:
        m = self.message.lower()
        return self.status in (400, 403) and (
            "service_disabled" in m or "has not been used" in m
            or "is disabled" in m or "api has not been enabled" in m
            or "accessnotconfigured" in m
        )


class BaseClient:
    """Pagination helpers on top of a single ``_request`` primitive."""

    def _request(self, method: str, url: str, params=None, body=None) -> Dict[str, Any]:
        raise NotImplementedError

    def get(self, url: str, params: Optional[dict] = None) -> Dict[str, Any]:
        return self._request("GET", url, params=params)

    def post(self, url: str, body: Optional[dict] = None) -> Dict[str, Any]:
        return self._request("POST", url, body=body or {})

    def list(self, url: str, key: str, params: Optional[dict] = None) -> List[dict]:
        """Follow ``nextPageToken`` and return the concatenated ``key`` arrays."""
        params = dict(params or {})
        out: List[dict] = []
        while True:
            data = self.get(url, params)
            out.extend(data.get(key, []) or [])
            token = data.get("nextPageToken")
            if not token:
                return out
            params["pageToken"] = token

    def agg_list(self, url: str, key: str, params: Optional[dict] = None) -> List[dict]:
        """Flatten Compute 'aggregatedList' responses (items: {scope: {key: [...]}})."""
        params = dict(params or {})
        out: List[dict] = []
        while True:
            data = self.get(url, params)
            for scope in (data.get("items") or {}).values():
                out.extend(scope.get(key, []) or [])
            token = data.get("nextPageToken")
            if not token:
                return out
            params["pageToken"] = token


class GcpClient(BaseClient):
    def __init__(self, mode: str = "adc", key_file: str = "", token: str = "", timeout: int = 60):
        try:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            from google.oauth2 import service_account
            from google.oauth2.credentials import Credentials
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "google-auth is required: pip install -r requirements.txt") from exc

        if mode == "key":
            creds = service_account.Credentials.from_service_account_file(key_file, scopes=SCOPES)
        elif mode == "token":
            creds = Credentials(token=token)
        else:
            creds, _ = google.auth.default(scopes=SCOPES)
        self._session = AuthorizedSession(creds)
        self._timeout = timeout

    def _request(self, method, url, params=None, body=None):
        resp = self._session.request(method, url, params=params, json=body, timeout=self._timeout)
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", {})
                msg = err.get("message", resp.text)
                reasons = " ".join(str(d.get("reason", "")) for d in err.get("details", [])
                                   if isinstance(d, dict))
                msg = f"{msg} {reasons}".strip()
            except ValueError:
                msg = resp.text
            raise ApiError(resp.status_code, msg, url)
        return resp.json() if resp.content else {}

    def discover_projects(self) -> List[str]:
        """Active projects visible to the credential."""
        projects = self.list("https://cloudresourcemanager.googleapis.com/v1/projects",
                             "projects", {"filter": "lifecycleState:ACTIVE"})
        return sorted(p["projectId"] for p in projects)
