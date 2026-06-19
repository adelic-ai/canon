"""Synthetic attack scenarios — correct-by-construction labeled instances spanning variants and telemetry
channels. The fidelity dataset: a single real campaign exercises one channel/variant, so it can only fairly
test a fraction of a technique's rules; these emit the labeled events of multiple variants across multiple
channels, so cross-channel rules (valuable defense-in-depth) get telemetry to fire on.

Honest scope: synthetic events validate rule LOGIC against *representative artifacts* (procdump → ``lsass.dmp``,
comsvcs → the GUID CallTrace), not field-realism. Realism is a recorded claim, not an assertion that results
transfer to the wild. No dependency on canon — the generator only produces labeled data.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    """One labeled (technique, variant) instance on a telemetry channel — its representative malicious events."""

    technique: str
    variant: str
    channel: str
    events: tuple[dict, ...]


def t1003_001_scenarios() -> list[Scenario]:
    """LSASS credential dumping (T1003.001), key variants across channels."""
    S = Scenario
    return [
        S("T1003.001", "comsvcs", "process_access", (
            {"EventID": "10", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
             "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
             "CallTrace": "C:\\Windows\\system32\\comsvcs.dll+0x1234|UNKNOWN", "GrantedAccess": "0x1FFFFF"},)),
        S("T1003.001", "procdump", "process_access", (
            {"EventID": "10", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
             "SourceImage": "C:\\tools\\procdump.exe", "GrantedAccess": "0x1438",
             "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+0x9c"},)),
        S("T1003.001", "procdump", "file_event", (
            {"EventID": "11", "Image": "C:\\tools\\procdump.exe",
             "TargetFilename": "C:\\Windows\\Temp\\lsass.dmp"},)),
        S("T1003.001", "taskmgr", "file_event", (
            {"EventID": "11", "Image": "C:\\Windows\\System32\\taskmgr.exe",
             "TargetFilename": "C:\\Users\\admin\\AppData\\Local\\Temp\\lsass.DMP"},)),
        S("T1003.001", "silentprocessexit", "registry", (
            {"EventID": "13", "EventType": "SetValue",
             "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                             "SilentProcessExit\\lsass.exe\\GlobalFlag", "Details": "DWORD (0x00000200)"},)),
    ]


def scenario_positives(scenarios: list[Scenario]) -> list[dict]:
    """Flatten scenarios to the labeled-positive event list a consumer's fidelity case takes."""
    return [e for s in scenarios for e in s.events]
