# FINDINGS — Kerberos ticket-hash detector on real patched-DC telemetry

**Date:** _TBD (fill after the capture)_
**Status:** in-progress — not yet run
**Verdict:** _TBD — one bold line here once the capture is in:_
  _H1 (field names): confirmed / refuted — real field names: `…`_
  _H2 (detector): confirmed / partial / refuted on real telemetry_
**Repo state:** canon @ `<sha>`; range @ `<sha>`
**Provenance:** see `run/<id>/provenance.json` (dc01/mbr01 build + KBs)

> Pre-registration lives in [`HYPOTHESIS.md`](./HYPOTHESIS.md). Do not edit the
> claims/nulls there after capture — record what happened here.

## H1 — Field names (the confirmation)

Real distinct `<Data Name=…>` fields on 4768/4769 (from `06`'s dump):

```
_TBD — paste the field list here_
```

| role | provisional guess | real field name | joins? |
|---|---|---|---|
| request (TGT presented, 4769) | `RequestTicketHash` | _TBD_ | _TBD_ |
| response (ticket issued, 4768) | `ResponseTicketHash` | _TBD_ | _TBD_ |

Action taken: _set FIELD_MAP + kerberos_tickets.py to `…` / left provisional because…_

## H2 — Detector on the real capture

Windows build / patch state at capture: _TBD (dc01 build, key KBs)_ → tier: _hash / metadata_.

| action | expected | observed verdict | pass? |
|---|---|---|---|
| baseline | no findings | _TBD_ | _TBD_ |
| golden ticket | `golden` / hash | _TBD_ | _TBD_ |
| pass-the-ticket | `pass-the-ticket` / hash | _TBD_ | _TBD_ |
| silver ticket | not flagged (blind spot) | _TBD_ | _TBD_ |

False positives on baseline: _TBD_. Misses: _TBD_.

## Analysis

_What the results mean; where they agree/disagree with the pre-registered claims;
the most surprising finding. If H1 refuted, what actually governs the hash
fields (KB level? a KDC audit registry setting?)._

## Conclusion

_One paragraph. The single sentence the next reader needs._

## Next steps

_e.g. push the confirmed field names into the Splunk/Sentinel ticket-integrity
pages; decide whether to build the member-side silver detector; whether run 2
warrants the Dockerized evaluator._
