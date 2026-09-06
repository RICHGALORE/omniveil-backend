from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .client import HumanProofAPIError, HumanProofClient
from .detector import DAWDetection, MacDAWDetector, project_path_token
from .evidence import EvidenceHasher, Fingerprint, quick_signature
from .profiles import AUDIO_EXPORT_EXTENSIONS


DEFAULT_CONFIG_PATH = Path.home() / ".omniveil" / "daw-bridge.json"
DEFAULT_STATE_PATH = Path.home() / ".omniveil" / "daw-bridge-state.json"


@dataclass
class BridgeConfig:
    poll_seconds: float = 2.0
    debounce_seconds: float = 4.0
    export_stability_seconds: float = 5.0
    export_scan_seconds: float = 5.0
    custom_project_extensions: set[str] = field(default_factory=set)
    export_roots: list[Path] = field(default_factory=lambda: [Path.home() / "Music"])

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "BridgeConfig":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text("utf-8"))
        return cls(
            poll_seconds=max(0.5, float(raw.get("poll_seconds", 2.0))),
            debounce_seconds=max(1.0, float(raw.get("debounce_seconds", 4.0))),
            export_stability_seconds=max(2.0, float(raw.get("export_stability_seconds", 5.0))),
            export_scan_seconds=max(2.0, float(raw.get("export_scan_seconds", 5.0))),
            custom_project_extensions={str(value) for value in raw.get("custom_project_extensions", [])},
            export_roots=[Path(value).expanduser() for value in raw.get("export_roots", [str(Path.home() / "Music")])],
        )


class BridgeState:
    def __init__(self, path: Path = DEFAULT_STATE_PATH):
        self.path = path
        self.data: dict[str, dict] = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text("utf-8"))
            except (json.JSONDecodeError, OSError):
                self.data = {}

    def session_for(self, project_key: str) -> str | None:
        value = self.data.get(project_key, {})
        session_id = value.get("session_id")
        return str(session_id) if session_id else None

    def remember(self, detection: DAWDetection, session_id: str) -> None:
        self.data[detection.project_key] = {
            "session_id": session_id,
            "daw_name": detection.daw_name,
            "project_extension": detection.project_extension,
            "updated_at": int(time.time()),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), "utf-8")


class ExportTracker:
    def __init__(self, stability_seconds: float):
        self.stability_seconds = stability_seconds
        self._observed: dict[str, tuple[int, int, float]] = {}
        self._emitted: set[str] = set()

    def stable_candidates(self, roots: list[Path], *, newer_than: float) -> list[Path]:
        now = time.time()
        stable: list[Path] = []
        seen_now: set[str] = set()
        for root in roots:
            if not root.exists():
                continue
            try:
                walker = root.rglob("*")
            except OSError:
                continue
            for path in walker:
                try:
                    if not path.is_file() or path.suffix.lower() not in AUDIO_EXPORT_EXTENSIONS:
                        continue
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_mtime < newer_than:
                    continue
                key = str(path)
                seen_now.add(key)
                previous = self._observed.get(key)
                signature = (stat.st_size, stat.st_mtime_ns)
                if previous and previous[:2] == signature:
                    unchanged_since = previous[2]
                else:
                    unchanged_since = now
                self._observed[key] = (signature[0], signature[1], unchanged_since)
                if (
                    key not in self._emitted
                    and now - unchanged_since >= self.stability_seconds
                    and stat.st_size > 0
                ):
                    self._emitted.add(key)
                    stable.append(path)
        for key in set(self._observed) - seen_now:
            self._observed.pop(key, None)
        return stable


class DAWBridge:
    def __init__(self, client: HumanProofClient, creator_id: str, config: BridgeConfig):
        self.client = client
        self.creator_id = creator_id
        self.config = config
        self.detector = MacDAWDetector(config.custom_project_extensions)
        self.hasher = EvidenceHasher()
        self.state = BridgeState()
        self.export_tracker = ExportTracker(config.export_stability_seconds)

        self.active: DAWDetection | None = None
        self.session_id: str | None = None
        self.session_started_epoch = 0.0
        self.last_quick_signature: tuple[int, int, int] | None = None
        self.last_project_hash: str | None = None
        self.pending_change_since: float | None = None
        self.last_export_scan = 0.0

    def _print(self, message: str) -> None:
        print(f"[HumanProof DAW] {message}", flush=True)

    def _ensure_session(self, detection: DAWDetection) -> str:
        remembered = self.state.session_for(detection.project_key)
        if remembered:
            try:
                existing = self.client.get_session(remembered)
                if existing.get("status") == "recording":
                    self._print(f"Reusing recording session {remembered} for {detection.project_name}")
                    return remembered
            except HumanProofAPIError:
                pass

        created = self.client.start_session(
            creator_id=self.creator_id,
            daw_name=detection.daw_name,
            process_name=detection.process_name,
            project_name=detection.project_name,
            project_extension=detection.project_extension,
            project_path_token=project_path_token(detection.project_path),
        )
        session_id = str(created["session_id"])
        self.state.remember(detection, session_id)
        self._print(f"Started {session_id}: {detection.daw_name} · {detection.project_name}")
        return session_id

    def _fingerprint_payload(self, detection: DAWDetection, fingerprint: Fingerprint, checkpoint: str) -> dict:
        return {
            "checkpoint": checkpoint,
            "daw_name": detection.daw_name,
            "project_name": detection.project_name,
            "project_extension": detection.project_extension,
            "project_path_token": project_path_token(detection.project_path),
            "sha256": fingerprint.sha256,
            "hash_mode": fingerprint.mode,
            "file_count": fingerprint.file_count,
            "total_bytes": fingerprint.total_bytes,
            "local_path_disclosed": False,
        }

    def _activate(self, detection: DAWDetection) -> None:
        self.active = detection
        self.session_id = self._ensure_session(detection)
        self.session_started_epoch = time.time()
        fingerprint = self.hasher.fingerprint(detection.project_path)
        self.last_project_hash = fingerprint.sha256
        self.last_quick_signature = quick_signature(detection.project_path)
        self.pending_change_since = None
        self.client.add_event(
            session_id=self.session_id,
            event_type="source_captured",
            daw_name=detection.daw_name,
            creator_id=self.creator_id,
            payload=self._fingerprint_payload(detection, fingerprint, "automatic_project_detected"),
        )
        self._print(f"Captured project fingerprint {fingerprint.sha256[:12]}…")

    def _record_save_if_stable(self) -> None:
        if not self.active or not self.session_id:
            return
        try:
            signature = quick_signature(self.active.project_path)
        except OSError:
            return

        if signature != self.last_quick_signature:
            self.last_quick_signature = signature
            self.pending_change_since = time.time()
            return

        if self.pending_change_since is None:
            return
        if time.time() - self.pending_change_since < self.config.debounce_seconds:
            return

        fingerprint = self.hasher.fingerprint(self.active.project_path)
        self.pending_change_since = None
        if fingerprint.sha256 == self.last_project_hash:
            return
        self.last_project_hash = fingerprint.sha256
        self.client.add_event(
            session_id=self.session_id,
            event_type="work_saved",
            daw_name=self.active.daw_name,
            creator_id=self.creator_id,
            payload=self._fingerprint_payload(self.active, fingerprint, "automatic_project_revision"),
        )
        self._print(f"Project revision recorded {fingerprint.sha256[:12]}…")

    def _scan_exports(self) -> None:
        if not self.active or not self.session_id:
            return
        now = time.time()
        if now - self.last_export_scan < self.config.export_scan_seconds:
            return
        self.last_export_scan = now

        roots = list(self.config.export_roots)
        project_parent = self.active.project_path.parent
        if project_parent not in roots:
            roots.append(project_parent)

        for path in self.export_tracker.stable_candidates(roots, newer_than=self.session_started_epoch):
            try:
                fingerprint = self.hasher.fingerprint(path)
                stat = path.stat()
            except OSError:
                continue
            self.client.add_event(
                session_id=self.session_id,
                event_type="work_exported",
                daw_name=self.active.daw_name,
                creator_id=self.creator_id,
                payload={
                    "checkpoint": "automatic_audio_export",
                    "daw_name": self.active.daw_name,
                    "filename": path.name,
                    "extension": path.suffix.lower(),
                    "sha256": fingerprint.sha256,
                    "bytes": stat.st_size,
                    "local_path_disclosed": False,
                },
            )
            self._print(f"Export recorded: {path.name} · {fingerprint.sha256[:12]}…")

    def tick(self) -> None:
        detection = self.detector.detect()
        if detection is None:
            if self.active is not None:
                self._print("DAW/project no longer detected; HumanProof session remains open for disclosure and final binding.")
                self.active = None
                self.session_id = None
                self.pending_change_since = None
            return

        if self.active is None or detection.project_key != self.active.project_key:
            self._activate(detection)
            return

        self.active = detection
        self._record_save_if_stable()
        self._scan_exports()

    def run(self) -> None:
        self._print("AutoDetect running. No project content is uploaded by the bridge.")
        while True:
            try:
                self.tick()
            except HumanProofAPIError as exc:
                self._print(str(exc))
            except KeyboardInterrupt:
                self._print("Stopped by user. Recording sessions are left open for safe finalization.")
                return
            except Exception as exc:  # keep the companion alive; never invent evidence
                self._print(f"Detector error: {type(exc).__name__}: {exc}")
            time.sleep(self.config.poll_seconds)


def main() -> int:
    if sys.platform != "darwin":
        print("HumanProof DAW AutoDetect v1 currently supports macOS.", file=sys.stderr)
        return 2

    base_url = os.getenv("OMNIVEIL_API_URL", "").strip()
    api_key = os.getenv("OMNIVEIL_API_KEY", "").strip()
    creator_id = os.getenv("OMNIVEIL_CREATOR_ID", "humanproof-daw-bridge").strip()
    if not base_url or not api_key:
        print("Set OMNIVEIL_API_URL and OMNIVEIL_API_KEY before starting the DAW bridge.", file=sys.stderr)
        return 2

    config = BridgeConfig.load()
    bridge = DAWBridge(
        HumanProofClient(base_url=base_url, api_key=api_key),
        creator_id=creator_id,
        config=config,
    )
    bridge.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
