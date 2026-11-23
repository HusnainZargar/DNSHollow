"""HTTP client for the manager (urllib only). Returns (status, json); status 0 = network error."""
import json
import ssl
import urllib.error
import urllib.request
from typing import Optional, Tuple

from . import __version__


class Client:
    def __init__(self, server: str, api_key: str, verify_tls: bool = True, timeout: float = 15.0):
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.ctx = None if verify_tls else ssl._create_unverified_context()

    def _call(self, method: str, path: str, body: Optional[dict] = None) -> Tuple[int, Optional[dict]]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.server + path, data=data, method=method, headers={
            "Content-Type": "application/json", "X-API-Key": self.api_key,
            "User-Agent": "dnshollow-agent/" + __version__})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, None
        except (urllib.error.URLError, OSError, ValueError):
            return 0, None

    def ingest(self, batch: dict):
        return self._call("POST", "/api/v1/agent/ingest", batch)

    def heartbeat(self, os_name: str, blocking: Optional[dict] = None):
        body = {"os": os_name, "agent_version": __version__}
        if blocking is not None:
            body["blocking"] = blocking
        return self._call("POST", "/api/v1/agent/heartbeat", body)
