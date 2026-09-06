from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DAWProfile:
    name: str
    process_tokens: tuple[str, ...]
    project_extensions: tuple[str, ...]


@dataclass(frozen=True)
class HardwareProfile:
    name: str
    category: str
    device_tokens: tuple[str, ...]


PROFILES: tuple[DAWProfile, ...] = (
    DAWProfile("Logic Pro", ("logic pro", "logic pro x"), (".logicx",)),
    DAWProfile("Ableton Live", ("ableton live",), (".als",)),
    DAWProfile("Pro Tools", ("pro tools",), (".ptx", ".ptf")),
    DAWProfile("FL Studio", ("fl studio",), (".flp",)),
    DAWProfile("Studio One", ("studio one",), (".song",)),
    DAWProfile("Cubase", ("cubase",), (".cpr",)),
    DAWProfile("Nuendo", ("nuendo",), (".npr",)),
    DAWProfile("REAPER", ("reaper",), (".rpp",)),
    DAWProfile("Bitwig Studio", ("bitwig studio", "bitwig"), (".bwproject",)),
    DAWProfile("GarageBand", ("garageband",), (".band",)),
    DAWProfile("Adobe Audition", ("adobe audition", "audition"), (".sesx",)),
    DAWProfile("Reason", ("reason",), (".reason",)),
    DAWProfile("Ardour", ("ardour",), (".ardour",)),
    DAWProfile("Renoise", ("renoise",), (".xrns",)),
    DAWProfile("LMMS", ("lmms",), (".mmp", ".mmpz")),
    DAWProfile("Cakewalk", ("cakewalk", "sonar"), (".cwp",)),
    DAWProfile("Tracktion Waveform", ("waveform", "tracktion"), (".tracktionedit",)),
    DAWProfile("Samplitude / Sequoia", ("samplitude", "sequoia"), (".vip",)),
    # Beat-production environments that behave like DAWs on desktop.
    DAWProfile("Akai MPC Desktop / MPC Beats", ("mpc beats", "mpc software", "mpc"), (".xpj",)),
    DAWProfile("Serato Studio", ("serato studio",), (".ssp",)),
    DAWProfile("Native Instruments Maschine", ("maschine 3", "maschine 2", "maschine"), (".mxprj", ".mprj")),
)


# Connected hardware is evidence about the production environment, not proof that
# the device itself created a specific work. The bridge only records it as context
# alongside an actual HumanProof session/project.
HARDWARE_PROFILES: tuple[HardwareProfile, ...] = (
    HardwareProfile("Akai MPC Key 61", "standalone_production_keyboard", ("mpc key 61",)),
    HardwareProfile("Akai MPC Key 37", "standalone_production_keyboard", ("mpc key 37",)),
    HardwareProfile("Akai MPC X / X SE", "standalone_mpc", ("mpc x se", "mpc x")),
    HardwareProfile("Akai MPC Live II", "standalone_mpc", ("mpc live ii", "mpc live 2", "mpc live")),
    HardwareProfile("Akai MPC One / One+", "standalone_mpc", ("mpc one+", "mpc one plus", "mpc one")),
    HardwareProfile("Akai MPC Studio", "mpc_controller", ("mpc studio",)),
    HardwareProfile("Akai MPC Touch", "mpc_controller", ("mpc touch",)),
    HardwareProfile("Native Instruments Maschine+", "standalone_groovebox", ("maschine+", "maschine plus")),
    HardwareProfile("Native Instruments Maschine", "production_controller", ("maschine mk3", "maschine mikro", "maschine")),
    HardwareProfile("Ableton Push 3", "standalone_production_controller", ("push 3", "ableton push")),
    HardwareProfile("Ableton Move", "standalone_production_instrument", ("ableton move", "move")),
    HardwareProfile("Roland FANTOM / FANTOM EX", "music_workstation", ("fantom ex", "fantom-06", "fantom-07", "fantom-08", "fantom")),
    HardwareProfile("Yamaha MONTAGE M", "music_workstation", ("montage m8x", "montage m7", "montage m6", "montage m")),
    HardwareProfile("Yamaha MODX+", "music_workstation", ("modx8+", "modx7+", "modx6+", "modx+", "modx")),
    HardwareProfile("Korg NAUTILUS", "music_workstation", ("nautilus",)),
    HardwareProfile("Korg KRONOS", "music_workstation", ("kronos",)),
    HardwareProfile("Roland MC-707", "groovebox", ("mc-707", "mc707")),
    HardwareProfile("Roland MC-101", "groovebox", ("mc-101", "mc101")),
    HardwareProfile("Novation Circuit Tracks", "groovebox", ("circuit tracks",)),
    HardwareProfile("Novation Circuit Rhythm", "groovebox", ("circuit rhythm",)),
    HardwareProfile("Elektron Digitakt", "groovebox_sampler", ("digitakt ii", "digitakt")),
    HardwareProfile("Elektron Octatrack", "performance_sampler", ("octatrack mkii", "octatrack")),
)


# Serato DJ products do not use a DAW-style song/project file, so they are kept
# as process-only production/performance environments. Detection may identify the
# running app, but HumanProof does not treat app launch alone as creation evidence.
PROCESS_ONLY_ENVIRONMENTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Serato DJ Pro", ("serato dj pro",)),
    ("Serato DJ Lite", ("serato dj lite",)),
)


KNOWN_PROJECT_EXTENSIONS = frozenset(
    extension
    for profile in PROFILES
    for extension in profile.project_extensions
)

AUDIO_EXPORT_EXTENSIONS = frozenset(
    {".wav", ".aif", ".aiff", ".mp3", ".m4a", ".flac"}
)


def normalize_process_name(value: str) -> str:
    return " ".join(value.lower().replace(".app", "").replace("_", " ").split())


def match_profile(process_name: str) -> DAWProfile | None:
    normalized = normalize_process_name(process_name)
    for profile in PROFILES:
        if any(token in normalized for token in profile.process_tokens):
            return profile
    return None


def match_process_only_environment(process_name: str) -> str | None:
    normalized = normalize_process_name(process_name)
    for name, tokens in PROCESS_ONLY_ENVIRONMENTS:
        if any(token in normalized for token in tokens):
            return name
    return None


def match_hardware_profile(device_name: str) -> HardwareProfile | None:
    normalized = normalize_process_name(device_name)
    for profile in HARDWARE_PROFILES:
        if any(token in normalized for token in profile.device_tokens):
            return profile
    return None
