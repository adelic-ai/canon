"""Source→OCSF adapters (step 2 of the OFF-able normalization waist).

Pins: the map produces dotted OCSF attribute paths; it is graded and lossy (never assumed
faithful); absent source fields become omitted attributes (→ NONE, not a false match); and
both source adapters target the SAME OCSF paths so a rule fires against either source."""

from detection.ocsf_adapter import (
    BROAD,
    CLOSE,
    ESLOGGER_ADAPTER,
    EXACT,
    PS_ADAPTER,
    SYSMON_ADAPTER,
    adapter,
)
from detection.vocab import NATIVE, OCSF, coheres


def _sysmon_eid1() -> dict:
    return {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 dump full",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ParentCommandLine": "cmd.exe /c dump",
        "ParentProcessId": "624",
        "ProcessId": "7508",
        "ProcessGuid": "{57be2c82-9496-64df-1909-000000000600}",
        "User": "PANDALAB\\pupy.godoy",
        "Hostname": "WIN-DC.pandalab.local",   # unmapped — no OCSF home in this slice
    }


def _ps_row() -> dict:
    return {"pid": "501", "ppid": "1", "user": "rick",
            "comm": "/usr/bin/ssh", "args": "ssh -i key user@host"}


def test_sysmon_normalizes_to_dotted_ocsf_paths():
    ocsf = SYSMON_ADAPTER.normalize(_sysmon_eid1())
    assert ocsf["process.file.path"] == "C:\\Windows\\System32\\rundll32.exe"
    assert ocsf["process.cmd_line"].startswith("rundll32.exe")
    assert ocsf["actor.process.file.path"] == "C:\\Windows\\System32\\cmd.exe"
    assert ocsf["actor.process.pid"] == "624"
    assert ocsf["actor.user.name"] == "PANDALAB\\pupy.godoy"
    # unmapped source fields do not cross
    assert all(not k.startswith("Hostname") for k in ocsf)
    assert "EventID" not in ocsf


def test_grades_record_loss_and_are_shown_on_demand():
    # exact where the field denotes the same thing with no loss
    assert SYSMON_ADAPTER.why("Image").grade == EXACT
    assert SYSMON_ADAPTER.why("Image").lossless
    # broad where the source field bundles more than the OCSF attribute (DOMAIN\user)
    user = SYSMON_ADAPTER.why("User")
    assert user.grade == BROAD and not user.lossless
    assert "domain" in user.rationale.lower()
    # close where there is minor loss (GUID format / ps truncation)
    assert SYSMON_ADAPTER.why("ProcessGuid").grade == CLOSE
    assert PS_ADAPTER.why("comm").grade == CLOSE
    # lossy_fields surfaces the non-exact edges to check for load-bearingness; the exact
    # edges (Image, ProcessId, paths, CurrentDirectory) are not in it.
    lossy = {m.source_field for m in SYSMON_ADAPTER.lossy_fields()}
    assert {"ProcessGuid", "User"} <= lossy
    assert not ({"Image", "ProcessId", "TargetImage", "SourceImage", "CurrentDirectory"} & lossy)
    # a field with no OCSF home returns None from why()
    assert SYSMON_ADAPTER.why("Hostname") is None


def test_absent_source_field_omits_the_attribute_not_a_false_match():
    # a ps snapshot has the parent pid but NOT the parent image/cmd — those attributes are
    # simply absent in the normalized view (→ NONE / missing telemetry for a rule reading
    # them), never a wrong value.
    ocsf = PS_ADAPTER.normalize(_ps_row())
    assert ocsf["actor.process.pid"] == "1"
    assert "actor.process.cmd_line" not in ocsf
    assert "actor.process.file.path" not in ocsf
    # the subject process is fully populated
    assert ocsf["process.file.path"] == "/usr/bin/ssh"
    assert ocsf["process.cmd_line"] == "ssh -i key user@host"


def test_both_sources_target_the_same_ocsf_vocabulary():
    # the cross-source reuse story: ps and Sysmon both produce process.cmd_line /
    # process.file.path, so a rule rewritten to OCSF reads the same field on either source.
    shared = {"process.cmd_line", "process.file.path", "process.pid", "actor.user.name"}
    ps = set(PS_ADAPTER.normalize(_ps_row()))
    sysmon = set(SYSMON_ADAPTER.normalize(_sysmon_eid1()))
    assert shared <= ps and shared <= sysmon


def test_coverage_reports_what_crossed_and_what_did_not():
    cov = SYSMON_ADAPTER.coverage(_sysmon_eid1())
    assert "Image" in cov["mapped"] and "User" in cov["mapped"]
    assert "Hostname" in cov["unmapped"] and "EventID" in cov["unmapped"]
    # a ps event is missing the Sysmon-only fields; for ps's own adapter nothing is absent
    assert PS_ADAPTER.coverage(_ps_row())["absent"] == []


def test_normalized_vocabulary_coheres_with_ocsf_not_native():
    v = SYSMON_ADAPTER.vocabulary()
    assert v.name == OCSF
    assert coheres(v, OCSF) and not coheres(v, NATIVE)
    # ps and Sysmon normalize into the same vocabulary name → they can be joined
    assert coheres(PS_ADAPTER.vocabulary(), SYSMON_ADAPTER.vocabulary())


def test_adapter_registry_and_unknown_source():
    assert adapter("sysmon") is SYSMON_ADAPTER
    assert adapter("ps") is PS_ADAPTER
    assert adapter("eslogger") is ESLOGGER_ADAPTER
    import pytest
    with pytest.raises(KeyError):
        adapter("zeek")


# ── eslogger (macOS Endpoint Security exec) — built against a real captured event ─────────
def _eslogger_exec(*, path_truncated: bool = False, team_id=None) -> dict:
    """A faithful trim of a real `eslogger exec` event: top-level `process` = caller,
    `event.exec.target` = the new process."""
    return {
        "event_type": 9,
        "process": {                                   # the caller
            "executable": {"path": "/sbin/launchd", "path_truncated": False},
            "audit_token": {"pid": 1, "euid": 0},
            "signing_id": "com.apple.xpc.launchd",
        },
        "thread": {"thread_id": 15388381},             # unmapped top-level key
        "mach_time": 12345,                            # unmapped top-level key
        "event": {"exec": {
            "args": ["mdworker_shared", "-s", "mdworker", "-c", "MDSImporterWorker"],
            "target": {                                # the new process
                "executable": {"path": "/usr/libexec/mdworker_shared",
                               "path_truncated": path_truncated},
                "audit_token": {"pid": 60561, "euid": 501},
                "start_time": "2026-06-19T07:28:29.061899Z",
                "signing_id": "com.apple.mdworker_shared",
                "team_id": team_id,
                "is_platform_binary": True,
            },
        }},
    }


def test_eslogger_caller_and_target_split_into_actor_and_process():
    ocsf = ESLOGGER_ADAPTER.normalize(_eslogger_exec())
    # target = the new process
    assert ocsf["process.file.path"] == "/usr/libexec/mdworker_shared"
    assert ocsf["process.pid"] == 60561
    # caller = the actor (parent) — full struct, no ppid-guessing
    assert ocsf["actor.process.file.path"] == "/sbin/launchd"
    assert ocsf["actor.process.pid"] == 1


def test_eslogger_argv_is_joined_into_cmd_line():
    ocsf = ESLOGGER_ADAPTER.normalize(_eslogger_exec())
    # argv array → one string (the transform the live data forced)
    assert ocsf["process.cmd_line"] == "mdworker_shared -s mdworker -c MDSImporterWorker"
    # and the edge is graded close because the join loses arg boundaries
    assert ESLOGGER_ADAPTER.why("event.exec.args").grade == CLOSE


def test_eslogger_path_grade_is_data_conditioned_on_truncation():
    m = ESLOGGER_ADAPTER.why("event.exec.target.executable.path")
    # base grade is the conservative worst case
    assert m.grade == CLOSE and not m.lossless
    # but on an untruncated path it earns exact; on a truncated one it stays close
    assert m.grade_for(_eslogger_exec(path_truncated=False)) == EXACT
    assert m.grade_for(_eslogger_exec(path_truncated=True)) == CLOSE


def test_eslogger_null_team_id_is_a_real_null_not_missing_telemetry():
    # platform binary → team_id null → developer_uid simply absent (not a wrong value)
    ocsf = ESLOGGER_ADAPTER.normalize(_eslogger_exec(team_id=None))
    assert "process.file.signature.developer_uid" not in ocsf
    # a third-party team_id does cross
    ocsf2 = ESLOGGER_ADAPTER.normalize(_eslogger_exec(team_id="ABCDE12345"))
    assert ocsf2["process.file.signature.developer_uid"] == "ABCDE12345"
    # the rationale names the real-null-vs-missing distinction
    assert "real" in ESLOGGER_ADAPTER.why("event.exec.target.team_id").rationale.lower()


def test_eslogger_has_no_parent_cmd_line_a_real_coverage_gap():
    # ES exec carries argv only for the target → no actor.process.cmd_line (a NONE), unlike
    # Sysmon's ParentCommandLine. The gap is real and surfaced, not hidden.
    ocsf = ESLOGGER_ADAPTER.normalize(_eslogger_exec())
    assert "actor.process.cmd_line" not in ocsf
    assert "actor.process.cmd_line" in SYSMON_ADAPTER.normalize(_sysmon_eid1())


def test_eslogger_user_is_uid_not_name_cross_source_impedance():
    ocsf = ESLOGGER_ADAPTER.normalize(_eslogger_exec())
    # macOS-ES gives a numeric uid; Windows gives a name — different OCSF attribute
    assert ocsf["actor.user.uid"] == 501
    assert "actor.user.name" not in ocsf
    assert "actor.user.name" in SYSMON_ADAPTER.normalize(_sysmon_eid1())


def test_eslogger_coverage_reports_unmapped_top_level_keys():
    cov = ESLOGGER_ADAPTER.coverage(_eslogger_exec())
    # top-level keys no mapping descends into are reported dropped
    assert "thread" in cov["unmapped"] and "mach_time" in cov["unmapped"]
    # consumed roots are not in unmapped
    assert "process" not in cov["unmapped"] and "event" not in cov["unmapped"]
    assert "event.exec.target.executable.path" in cov["mapped"]


def test_eslogger_coheres_with_sysmon_for_cross_source_reuse():
    # all three sources normalize into the OCSF vocabulary → joinable
    assert coheres(ESLOGGER_ADAPTER.vocabulary(), SYSMON_ADAPTER.vocabulary())
    assert coheres(ESLOGGER_ADAPTER.vocabulary(), OCSF)
    # the shared subject-process fields a cross-source rule reads are present from eslogger
    shared = {"process.file.path", "process.cmd_line", "process.pid"}
    assert shared <= set(ESLOGGER_ADAPTER.normalize(_eslogger_exec()))
