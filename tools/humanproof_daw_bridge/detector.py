from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .profiles import KNOWN_PROJECT_EXTENSIONS, DAWProfile, match_profile, normalize_process_name


@dataclass(frozen=True)
class RunningProcess:
    pid: int
    command: str


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
    """Detect a running DAW by process identity + an actually-open project file.

    The detector deliberately does not treat "DAW process is running" as creation
    evidence. It requires an open project path from the process file table. Known
    DAWs get a friendly product name; an unknown foreground app can still be
    detected when it has an open file matching a known/custom DAW project format.
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

    def project_root_from_open_path(self, path: Path) -> Path | None:
        # Handles package-style projects such as Foo.logicx/... as well as
        # ordinary single-file projects such as Song.als or Session.ptx.
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

        # Prefer the most recently changed open project when multiple projects are
        # open. Failure to stat falls back to a deterministic lexical ordering.
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

        # Foreground wins. Then known profile. Then recent project modification.
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
