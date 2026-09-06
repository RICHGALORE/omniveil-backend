from pathlib import Path

from tools.humanproof_daw_bridge import detector as detector_module
from tools.humanproof_daw_bridge.detector import MacDAWDetector, RunningProcess, project_path_token
from tools.humanproof_daw_bridge.evidence import EvidenceHasher
from tools.humanproof_daw_bridge.profiles import (
    match_hardware_profile,
    match_process_only_environment,
    match_profile,
)


def test_known_daw_profiles_match_without_version_specific_names():
    assert match_profile("/Applications/Logic Pro.app/Contents/MacOS/Logic Pro").name == "Logic Pro"
    assert match_profile("Ableton Live 13 Suite").name == "Ableton Live"
    assert match_profile("REAPER").name == "REAPER"
    assert match_profile("MPC Beats").name == "Akai MPC Desktop / MPC Beats"
    assert match_profile("Serato Studio").name == "Serato Studio"
    assert match_profile("Some Unknown Audio App") is None


def test_serato_dj_apps_are_detectable_without_faking_project_evidence():
    assert match_process_only_environment("Serato DJ Pro") == "Serato DJ Pro"
    assert match_process_only_environment("Serato DJ Lite") == "Serato DJ Lite"
    assert match_profile("Serato DJ Pro") is None


def test_full_beat_hardware_profiles_match_connected_device_names():
    assert match_hardware_profile("MPC Key 61").name == "Akai MPC Key 61"
    assert match_hardware_profile("MPC Live II").name == "Akai MPC Live II"
    assert match_hardware_profile("MASCHINE+").name == "Native Instruments Maschine+"
    assert match_hardware_profile("NAUTILUS").name == "Korg NAUTILUS"
    assert match_hardware_profile("MONTAGE M8x").name == "Yamaha MONTAGE M"


def test_usb_profiler_name_collection_does_not_require_serial_numbers():
    names = MacDAWDetector._collect_usb_names(
        {
            "SPUSBDataType": [
                {
                    "_name": "USB Bus",
                    "_items": [
                        {"_name": "MPC Key 37", "manufacturer": "Akai Professional"},
                        {"product_name": "MASCHINE+"},
                    ],
                }
            ]
        }
    )
    assert "MPC Key 37" in names
    assert "MASCHINE+" in names
    assert all("serial" not in value.lower() for value in names)


def test_logic_package_root_is_recovered_from_open_internal_file(monkeypatch):
    monkeypatch.setattr(detector_module.sys, "platform", "darwin")
    detector = MacDAWDetector()
    nested = Path("/Users/creator/Music/Turn Me Up.logicx/Alternatives/000/ProjectData")
    assert detector.project_root_from_open_path(nested) == Path("/Users/creator/Music/Turn Me Up.logicx")


def test_mpc_and_serato_studio_project_extensions_are_supported(monkeypatch):
    monkeypatch.setattr(detector_module.sys, "platform", "darwin")
    detector = MacDAWDetector()
    assert detector.project_root_from_open_path(Path("/Users/creator/Music/Beat.xpj")) == Path("/Users/creator/Music/Beat.xpj")
    assert detector.project_root_from_open_path(Path("/Users/creator/Music/Beat.ssp")) == Path("/Users/creator/Music/Beat.ssp")


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
