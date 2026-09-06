from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class HumanProofAPIError(RuntimeError):
    status: int
    detail: str

    def __str__(self) -> str:
        return f"HumanProof API {self.status}: {self.detail}"


class HumanProofClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "user-agent": "OmniVeil-HumanProof-DAW-AutoDetect/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise HumanProofAPIError(exc.code, body or exc.reason) from exc
        except urllib.error.URLError as exc:
            raise HumanProofAPIError(0, str(exc.reason)) from exc

    def start_session(
        self,
        *,
        creator_id: str,
        daw_name: str,
        process_name: str,
        project_name: str,
        project_extension: str,
        project_path_token: str,
    ) -> dict:
        return self._request(
            "POST",
            "/api/v1/humanproof/sessions",
            {
                "creator_id": creator_id,
                "source_type": "daw",
                "source_name": daw_name,
                "location": {"level": "none"},
                "payload": {
                    "workflow": "HumanProof DAW AutoDetect v1",
                    "daw_name": daw_name,
                    "process_name": process_name,
                    "project_name": project_name,
                    "project_extension": project_extension,
                    "project_path_token": project_path_token,
                    "local_path_disclosed": False,
                    "evidence_policy": "automatic_local_hashes_only",
                },
            },
        )

    def get_session(self, session_id: str) -> dict:
        return self._request("GET", f"/api/v1/humanproof/sessions/{session_id}")

    def add_event(
        self,
        *,
        session_id: str,
        event_type: str,
        daw_name: str,
        creator_id: str,
        payload: dict,
    ) -> dict:
        return self._request(
            "POST",
            f"/api/v1/humanproof/sessions/{session_id}/events",
            {
                "event_type": event_type,
                "source_type": "daw",
                "source_name": daw_name,
                "creator_id": creator_id,
                "payload": payload,
            },
        )
