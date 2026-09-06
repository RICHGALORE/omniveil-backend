from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .profiles import (
    KNOWN_PROJECT_EXTENSIONS,
    DAWProfile,
    HardwareProfile,
    match_hardware_profile,
    match_process_only_environment,
    match_profile,
    normalize_process_name,
)


@dataclass(frozen=True)
class RunningProcess:
    pid: int
    command: str


@dataclass(frozen=True)
class ConnectedHardware:
    name: str
    category: str
    observed_name: str
    profile: HardwareProfile


@dataclass(frozen=True)
class DAWDetection:
    pid: int
    process_name: str
    daw_name: str
    project_path: Path
    project_extension: str
    profile: DAWProfile | None
    foreground: bool

    @property
    def project_name(self) -> str:
        return self.project_path.name

    @property
    def project_key(self) -> str:
        return hashlib.sha256(str(self.project_path).encode("utf-8")).hexdigest()


class MacDAWDetector:
    """Detect desktop production apps and connected beat-production hardware.

    DAW creation evidence still requires an actually-open project file. Connected
    hardware and process-only apps such as Serato DJ are exposed as environment
    context only; their presence is never treated as proof that creative work was
    performed.
    """

    def __init__(self, custom_extensions: set[str] | None = None):
        if sys.platform != "darwin":
            raise RuntimeError("DAW AutoDetect v1 currently requires macOS")
        self.project_extensions = set(KNOWN_PROJECT_EXTENSIONS)
        for extension in custom_extensions or set():
            normalized = extension.lower()
            if not normalized.startswith("."):
                normalized = f".{normalized}"
            self.project_extensions.add(normalized)

    def foreground_app_name(self) -> str | None:
        script = (
            'tell application "System Events" to get name of first application process '
            "whose frontmost is true"
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        name = result.stdout.strip()
        return name or None

    def running_processes(self) -> list[RunningProcess]:
        try:
            result = subprocess.run(
                ["ps", "-axo", "pid=,comm="],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError):
            return []

        processes: list[RunningProcess] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            pid_text, _, command = line.partition(" ")
            try:
                pid = int(pid_text)
            except ValueError:
                continue
            processes.append(RunningProcess(pid=pid, command=command.strip()))
        return processes

    def running_process_only_environments(self) -> list[str]:
        """Identify supported apps that do not expose DAW-style project files."""
        names: list[str] = []
        for process in self.running_processes():
            display_name = Path(process.command).name
            environment = match_process_only_environment(display_name)
            if environment and environment not in names:
                names.append(environment)
        return names

    def open_files(self, pid: int) -> list[Path]:
        try:
            result = subprocess.run(
                ["lsof", "-Fn", "-p", str(pid)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError):
            return []

        paths: list[Path] = []
        for line in result.stdout.splitlines():
            if not line.startswith("n/"):
                continue
            raw = line[1:]
            if raw.startswith("/dev/") or raw.startswith("/System/"):
                continue
            paths.append(Path(raw))
        return paths

    @staticmethod
    def _collect_usb_names(value) -> list[str]:
        names: list[str] = []
        if isinstance(value, dict):
            for key in ("_name", "product_name", "manufacturer"):
                item = value.get(key)
                if isinstance(item, str) and item.strip():
                    names.append(item.strip())
            for child in value.values():
                names.extend(MacDAWDetector._collect_usb_names(child))
        elif isinstance(value, list):
            for child in value:
                names.extend(MacDAWDetector._collect_usb_names(child))
        return names

    def connected_hardware(self) -> list[ConnectedHardware]:
        """Return supported USB-connected production hardware without serial IDs."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            raw = json.loads(result.stdout)
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
            return []

        detections: list[ConnectedHardware] = []
        seen: set[str] = set()
        for observed in self._collect_usb_names(raw):
            profile = match_hardware_profile(observed)
            if profile is None or profile.name in seen:
                continue
            seen.add(profile.name)
            detections.append(
                ConnectedHardware(
                    name=profile.name,
                    category=profile.category,
                    observed_name=observed,
                    profile=profile,
                )
            )
        return detections

    def project_root_from_open_path(self, path: Path) -> Path | None:
        # Handles package-style projects such as Foo.logicx/... as well as
        # ordinary single-file projects such as Song.als, Session.ptx, MPC .xpj,
        # and Serato Studio .ssp projects.
        parts = path.parts
        for index, part in enumerate(parts):
            suffix = Path(part).suffix.lower()
            if suffix in self.project_extensions:
                return Path(*parts[: index + 1])
        suffix = path.suffix.lower()
        if suffix in self.project_extensions:
            return path
        return None

    def _candidate_for_process(
        self,
        process: RunningProcess,
        foreground_name: str | None,
    ) -> DAWDetection | None:
        display_name = Path(process.command).name
        profile = match_profile(display_name)
        foreground = False
        if foreground_name:
            foreground = (
                normalize_process_name(foreground_name)
                in normalize_process_name(display_name)
                or normalize_process_name(display_name)
                in normalize_process_name(foreground_name)
            )

        # Avoid lsof'ing every process. Known DAWs are always eligible; otherwise
        # inspect only the foreground app for the generic project-file fallback.
        if profile is None and not foreground:
            return None

        roots: dict[str, Path] = {}
        for path in self.open_files(process.pid):
            root = self.project_root_from_open_path(path)
            if root is not None:
                roots[str(root)] = root
        if not roots:
            return None

        def score(project: Path) -> tuple[int, str]:
            try:
                return (project.stat().st_mtime_ns, str(project))
            except OSError:
                return (0, str(project))

        project = max(roots.values(), key=score)
        return DAWDetection(
            pid=process.pid,
            process_name=display_name,
            daw_name=profile.name if profile else foreground_name or display_name,
            project_path=project,
            project_extension=project.suffix.lower(),
            profile=profile,
            foreground=foreground,
        )

    def detect(self) -> DAWDetection | None:
        foreground = self.foreground_app_name()
        candidates: list[DAWDetection] = []
        for process in self.running_processes():
            candidate = self._candidate_for_process(process, foreground)
            if candidate:
                candidates.append(candidate)
        if not candidates:
            return None

        def score(candidate: DAWDetection) -> tuple[int, int, int]:
            try:
                modified = candidate.project_path.stat().st_mtime_ns
            except OSError:
                modified = 0
            return (
                1 if candidate.foreground else 0,
                1 if candidate.profile is not None else 0,
                modified,
            )

        return max(candidates, key=score)


def project_path_token(path: Path) -> str:
    """Return a stable privacy-safe token instead of disclosing the local path."""
    return hashlib.sha256(str(path.expanduser().resolve()).encode("utf-8")).hexdigest()
