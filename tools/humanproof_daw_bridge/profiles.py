from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DAWProfile:
    name: str
    process_tokens: tuple[str, ...]
    project_extensions: tuple[str, ...]


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
