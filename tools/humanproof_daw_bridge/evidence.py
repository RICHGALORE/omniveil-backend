from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class Fingerprint:
    sha256: str
    file_count: int
    total_bytes: int
    mode: str


class EvidenceHasher:
    """Incremental, local-only cryptographic hashing for DAW project evidence."""

    def __init__(self):
        self._cache: dict[str, tuple[int, int, str]] = {}

    def hash_file(self, path: Path) -> str:
        stat = path.stat()
        key = str(path)
        cached = self._cache.get(key)
        signature = (stat.st_size, stat.st_mtime_ns)
        if cached and cached[:2] == signature:
            return cached[2]

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
        value = digest.hexdigest()
        self._cache[key] = (stat.st_size, stat.st_mtime_ns, value)
        return value

    def fingerprint(self, path: Path) -> Fingerprint:
        if path.is_file():
            return Fingerprint(
                sha256=self.hash_file(path),
                file_count=1,
                total_bytes=path.stat().st_size,
                mode="full_file_sha256",
            )

        digest = hashlib.sha256()
        file_count = 0
        total_bytes = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".Trash"))
            for filename in sorted(files):
                candidate = Path(root) / filename
                try:
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    stat = candidate.stat()
                    relative = candidate.relative_to(path).as_posix()
                    file_hash = self.hash_file(candidate)
                except OSError:
                    continue
                file_count += 1
                total_bytes += stat.st_size
                digest.update(relative.encode("utf-8"))
                digest.update(b"\0")
                digest.update(str(stat.st_size).encode("ascii"))
                digest.update(b"\0")
                digest.update(file_hash.encode("ascii"))
                digest.update(b"\n")
        return Fingerprint(
            sha256=digest.hexdigest(),
            file_count=file_count,
            total_bytes=total_bytes,
            mode="recursive_content_sha256",
        )


def quick_signature(path: Path) -> tuple[int, int, int]:
    """Cheap change detector; full cryptographic hash is computed after debounce."""
    if path.is_file():
        stat = path.stat()
        return (1, stat.st_size, stat.st_mtime_ns)

    count = 0
    total_bytes = 0
    newest = 0
    for root, _, files in os.walk(path):
        for filename in files:
            candidate = Path(root) / filename
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                stat = candidate.stat()
            except OSError:
                continue
            count += 1
            total_bytes += stat.st_size
            newest = max(newest, stat.st_mtime_ns)
    return (count, total_bytes, newest)
