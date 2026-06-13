r"""Structural detectors for faker-kerberos' other four labeled attack types.

The relational/structural counterpart to the statistical (entropy×conformal) detectors in
`src/detection/`. Each is a deterministic signature over the events — not a population outlier
test — grounded in the corpus's actual field values:

  Ticket_Encryption_Type: 0x12 = AES256 (25,848), 0x17 = RC4 (123, rare → strong signal)
  Failure_Code/Status:     0x18 = pre-auth failed / bad password (311 = the spray failures)
  hour-of-day:             07–18 business (~2000/hr), 19–06 off-hours (40–95/hr)

  kerberoasting   one account requesting MANY distinct RC4 service tickets   (T1558.003)
  enc-downgrade   RC4 used by a normally-AES account, but NOT at roast scale  (T1558)
  password-spray  one source IP failing auth across MANY distinct accounts    (T1110.003)
  off-hours       a strong day-shift account with rare off-hours activity     (T1078)

Thresholds are round and defensible (not fitted to the labels): roast ≥10 distinct RC4
services; spray ≥10 distinct failed accounts; off-hours = ≥95% business-hours baseline.

Run:  .venv/bin/python packages/detection/experiments/kerberos_behavior_detectors.py
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from kerberos_orphan_real import load

RC4 = "0x17"
AES = "0x12"
FAIL = "0x18"
BUSINESS = range(7, 19)            # 07:00–18:59 (from the hour histogram)
_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _hour(r: dict) -> int:
    try:
        return datetime.strptime(r["_time"], _FMT).hour
    except (ValueError, KeyError):
        return -1


def kerberoasting(rows: list[dict], min_services: int = 10) -> set[str]:
    """Account requesting many distinct service tickets with RC4 (downgrade to a crackable hash)."""
    by_acct: dict[str, set] = defaultdict(set)
    for r in rows:
        if r.get("EventCode") == "4769" and r.get("Ticket_Encryption_Type") == RC4:
            by_acct[r["Account_Name"]].add(r.get("Service_Name", ""))
    return {a for a, svcs in by_acct.items() if len(svcs) >= min_services}


def enc_downgrade(rows: list[dict], max_services: int = 3) -> set[str]:
    """RC4 used by an account that otherwise uses AES — a targeted downgrade, NOT roast-scale
    fan-out (so it's separated from kerberoasting by the service-count ceiling)."""
    rc4: dict[str, set] = defaultdict(set)
    aes: dict[str, int] = defaultdict(int)
    for r in rows:
        if r.get("EventCode") in ("4768", "4769"):
            enc = r.get("Ticket_Encryption_Type")
            if enc == RC4:
                rc4[r["Account_Name"]].add(r.get("Service_Name", ""))
            elif enc == AES:
                aes[r["Account_Name"]] += 1
    return {a for a, svcs in rc4.items() if 0 < len(svcs) <= max_services and aes.get(a, 0) > 0}


def password_spray(rows: list[dict], min_accounts: int = 10) -> set[str]:
    """One source IP failing pre-auth across many distinct accounts."""
    by_ip: dict[str, set] = defaultdict(set)
    for r in rows:
        if r.get("Failure_Code") == FAIL or r.get("Status") == FAIL:
            ip = r.get("Client_Address", "")
            if ip:
                by_ip[ip].add(r.get("Account_Name", ""))
    return {ip for ip, accts in by_ip.items() if len(accts) >= min_accounts}


def off_hours(rows: list[dict], min_business_ratio: float = 0.95, min_events: int = 10) -> set[str]:
    """A strong day-shift account (≥min_business_ratio of its activity in business hours) that
    nonetheless has off-hours events — the rare deviation from a per-entity baseline."""
    biz: dict[str, int] = defaultdict(int)
    off: dict[str, int] = defaultdict(int)
    for r in rows:
        acct = r.get("Account_Name", "")
        if _hour(r) in BUSINESS:
            biz[acct] += 1
        else:
            off[acct] += 1
    fired = set()
    for acct, n_off in off.items():
        total = biz.get(acct, 0) + n_off
        if total >= min_events and biz.get(acct, 0) / total >= min_business_ratio:
            fired.add(acct)
    return fired


def main() -> None:
    rows = load()
    for name, fired in (("kerberoasting", kerberoasting(rows)), ("enc_downgrade", enc_downgrade(rows)),
                        ("password_spray", password_spray(rows)), ("off_hours", off_hours(rows))):
        print(f"{name:16} fired on {len(fired):2}: {sorted(fired)}")


if __name__ == "__main__":
    main()
