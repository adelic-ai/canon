"""Synthetic attack scenarios — correct-by-construction labeled instances for the fidelity axis.

The first dataset-generator slice aimed at FIDELITY (``design/dataset_generator_product.md``). The single OTRF
campaign exercises ONE channel (process_access) and ONE variant (comsvcs), so it can only fairly test a
fraction of a technique's rules. These scenarios emit the labeled events of MULTIPLE variants across MULTIPLE
telemetry channels — so the cross-channel rules (the ``missing-telemetry`` ones, which are *valuable*
defense-in-depth, not noise) get telemetry to fire on, and we can measure whether every key variant is caught,
ideally via more than one channel. Labels are correct-by-construction (the generator placed the malicious
events).

Honest scope (the product doc's standing caveat): synthetic events validate rule LOGIC against *representative
artifacts*, not field-realism — a scenario uses each variant's documented artifact (procdump → ``lsass.dmp``,
comsvcs → the GUID CallTrace). Realism is a recorded claim, never an assertion that results transfer to the wild.
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
    """LSASS credential dumping (T1003.001), key variants across channels — the multi-channel/multi-variant
    corpus the single OTRF campaign can't provide."""
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
    """Flatten scenarios to the labeled-positive event list a fidelity case consumes."""
    return [e for s in scenarios for e in s.events]


def variant_coverage(scenarios: list[Scenario], *, sigma_root=None) -> list[dict]:
    """Per (variant, channel): is there ≥1 evaluable Sigma rule that catches its events, and which. The
    defense-in-depth view the single-campaign scorecard can't give — every key variant should be caught,
    ideally via its own channel."""
    from detection.sigma_eval import evaluate_rule, is_evaluable
    from detection.sigma_panel import SIGMA, gather

    root = sigma_root or SIGMA
    out = []
    for s in scenarios:
        rules = [(p, r) for p, r in gather(s.technique, root=root) if is_evaluable(r)]
        catchers = [p.name for p, r in rules if any(evaluate_rule(r, e)["fires"] for e in s.events)]
        out.append({"technique": s.technique, "variant": s.variant, "channel": s.channel,
                    "caught": bool(catchers), "catchers": catchers})
    return out
