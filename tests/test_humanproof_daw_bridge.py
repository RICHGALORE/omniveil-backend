from pathlib import Path

from tools.humanproof_daw_bridge import detector as detector_module
from tools.humanproof_daw_bridge.detector import MacDAWDetector, RunningProcess, project_path_token
from tools.humanproof_daw_bridge.evidence import EvidenceHasher
from tools.humanproof_daw_bridge.profiles import match_profile


def test_known_daw_profiles_match_without_version_specific_names():
    assert match_profile("/Applications/Logic Pro.app/Contents/MacOS/Logic Pro").name == "Logic Pro"
    assert match_profile("Ableton Live 13 Suite").name == "Ableton Live"
    assert match_profile("REAPER") .name == "REAPER"
    assert match_profile("Some Unknown Audio App") is None


def test_logic_package_root_is_recovered_from_open_internal_file(monkeypatch):
    monkeypatch.setattr(detector_module.sys, "platform", "darwin")
    detector = MacDAWDetector()
    nested = Path("/Users/creator/Music/Turn Me Up.logicx/Alternatives/000/ProjectData")
    assert detector.project_root_from_open_path(nested) == Path("/Users/creator/Music/Turn Me Up.logicx")


def test_unknown_foreground_daw_can_be_detected_by_custom_project_extension(monkeypatch):
    monkeypatch.setattr(detector_module.sys, "platform", "darwin")
    detector = MacDAWDetector({".futureproject"})
    monkeypatch.setattr(
        detector,
        "open_files",
        lambda _pid: [Path("/Users/creator/Music/Next.futureproject")],
    )
    candidate = detector._candidate_for_process(
        RunningProcess(pid=1234, command="/Applications/FutureDAW"),
        "FutureDAW",
    )
    assert candidate is not None
    assert candidate.daw_name == "FutureDAW"
    assert candidate.project_extension == ".futureproject"
    assert candidate.profile is None


def test_project_path_token_is_stable_and_does_not_disclose_path(tmp_path):
    project = tmp_path / "private.logicx"
    project.mkdir()
    token = project_path_token(project)
    assert token == project_path_token(project)
    assert str(project) not in token
    assert len(token) == 64


def test_recursive_project_fingerprint_changes_when_content_changes(tmp_path):
    project = tmp_path / "Song.logicx"
    project.mkdir()
    data = project / "ProjectData"
    data.write_bytes(b"version-one")

    hasher = EvidenceHasher()
    first = hasher.fingerprint(project)
    data.write_bytes(b"version-two")
    second = hasher.fingerprint(project)

    assert first.mode == "recursive_content_sha256"
    assert first.file_count == 1
    assert second.sha256 != first.sha256
