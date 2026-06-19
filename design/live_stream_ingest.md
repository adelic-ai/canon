# Live stream ingest — reading a forgetful source continuously

**Status:** design, not built. Captured 2026-06-19 from the live-macOS / eslogger thread.
**Relates to:** [[retention_and_aging]] (what the stream's accumulated state ages into —
this doc is the *intake*, that one is the *outflow*), [[ocsf_ingest_normalization]] (each
streamed event is normalized through a source→OCSF adapter), [[engine_workspace_boundary]]
(a running monitor is one engine process bound to one workspace), [[self_validation_architecture]]
(feed-liveness = custody, §6; per-event vs windowed maps to verifier vs surfacer),
[[verdict_coverage_space]] (a feed gap is a NONE, not a FALSE).

## The source forgets — so continuous capture is the only history

macOS Endpoint Security (and `eslogger` over it) **retains nothing**. It is a real-time
subscription: each event is delivered to subscribed clients the instant it happens and then
dropped. Kill the reader and the stream stops; there is no buffer, no ring, no look-back.
Events before the subscription started, or during any window when no client was subscribed,
were never delivered and are unrecoverable. (`osquery`'s `es_process_events` is the same
model; Unified Logging persists but is thinner — no full command lines; OpenBSM persists only
if configured.) **You keep exactly what you capture.** A gap when the monitor is down is an
honest **NONE** for that window — not FALSE — which is the feed-liveness signal the temporal
fold already wants ([[self_validation_architecture]] §6: a live, unbroken feed *is* intact
chain-of-custody).

## Raw ingest is trivial; "live detection" splits into two shapes

Reading the stream is straightforward: `eslogger exec` emits NDJSON (one event per line);
read line-by-line, normalize each through the eslogger→OCSF adapter
([[ocsf_ingest_normalization]]), feed the result onward. canon already *models* a live feed
even though it doesn't yet read one — `ingest.attest(..., feed_live=True)` exists; a real
stream supplies that signal instead of hardcoding it.

What "detect live" means is **not one thing** — it splits exactly along the verifier/surfacer
axis:

- **Sigma round = per-event, genuinely streamable.** Each rule is a predicate on one event.
  As each event arrives: normalize → evaluate the selected rules → emit a verdict on a hit.
  No window, no accumulated state. This is the *verifier* path; it works on a single event.
- **Battery = windowed micro-batch.** It is a rarity-against-population statistic; one event
  has no rarity. So it runs over a **sliding window** (trailing N minutes / N events),
  recomputed periodically. "Live" here = "re-run the battery every interval over the trailing
  window," not "score each event as it lands." This is the *surfacer* path; it needs a
  population. This is not a limitation to fix — it is what a statistical surfacer *is*.

## The reader loop

```
eslogger exec ──(root)──▶  NDJSON  ──(unprivileged reader)──▶  normalize (eslogger→OCSF)
                                                                  │
                                          ┌───────────────────────┴───────────────────────┐
                                  per-event: fire the Sigma round            every interval: run the battery
                                  → verdict on a hit (streamable)            over the trailing window (micro-batch)
                                                                  │
                                                         emit verdicts → workspace store ([[retention_and_aging]])
```

The body is a generator that follows the source like `tail -f` (`iter_ndjson(path)` yielding
parsed events as lines arrive), feeding the two consumers above. The per-event consumer is
stateless; the windowed consumer holds the trailing window (the only in-memory state).

## Continuous = a daemon: one stateful engine process per host, bound to a workspace

"Run it continuously" means a **long-running process**, not the batch CLI we run today
(invoke → load list → fire → exit). It is:

- **the same engine code** — you don't fork or re-checkout canon; you host the library in a
  persistent process whose loop is the reader above;
- **detached from any interactive session** — it must outlive the shell that started it, so it
  runs under a process manager;
- **stateful** — the trailing window (and the feed-liveness signal) live in the process;
  batch runs reconstruct everything from the input each time, a daemon accumulates;
- **bound to a workspace** ([[engine_workspace_boundary]]) — the per-host state (baselines,
  verdict store, vocab/adapter pins, retention horizons) is workspace, not engine. One engine
  process pointed at one workspace = one **instance**. N hosts → N instances → N workspaces,
  one engine — the enterprise-ingest picture at scale; for one Mac, a single daemon.

On macOS the natural form is **launchd**, and it maps cleanly onto a privilege split that is
also good hygiene — the analysis process never runs as root:

- a root **LaunchDaemon** runs `eslogger exec` and writes the stream (collection; needs root +
  Full Disk Access);
- an unprivileged **LaunchAgent** runs the canon reader, tailing the stream (analysis; no root).

Two managed services, one pipe (a file or FIFO) between them.

## How we wire it — the transport (the concrete "how")

The topology above leaves one load-bearing decision: *what carries bytes from the root
producer to the unprivileged reader.* Three options, judged against canon's own rule —
**a gap must be an honest NONE, never silently-lost data:**

- **FIFO (named pipe).** Zero disk, true streaming — but writes **drop** when no reader is
  attached, so a reader restart loses every event in between (a *silent* gap, not a recorded
  one), there is no replay, and the small pipe buffer stalls `eslogger` under backpressure.
- **Append file + reader byte-offset (chosen).** `eslogger` appends; the reader tails from its
  last **checkpointed offset**. A reader restart resumes with **no gap**; producer and consumer
  are decoupled (no backpressure stall); the only gap is genuine downtime — an honest NONE the
  feed-liveness signal records. Cost is disk growth, already governed by
  [[retention_and_aging]] (rotate + carry the offset across rotations).
- **Unix domain socket.** True streaming with real backpressure, but needs a spool to survive
  reader restarts — more moving parts for no NONE-honesty gain over the file.

**Chosen: append-file + offset checkpoint.** In a system whose point is honest NONE vs lost
data, losing replay-across-restart (the FIFO failure) is the wrong trade, and the file's only
downside (growth) is already a solved problem here. Concretely:

```
LaunchDaemon (root):     eslogger exec  >>  $WORKSPACE/stream/exec.ndjson   (append; logrotate-style rotation)
LaunchAgent  (user):     reader tails exec.ndjson from a checkpointed byte offset
                         → on each complete line: normalize → per-event Sigma fire
                         → on an interval timer: battery over the trailing window
                         → fsync the offset after a processed batch (the resume point)
```

- **Restart = resume, not gap.** The checkpointed offset is the reader's durable position;
  after a crash it re-opens the file and seeks there. Events written while the reader was down
  are still on disk → replayed, not lost. Reader downtime that *exceeds retention* (the file
  rotated past the offset) is the one real gap — and it is recorded as a NONE, not hidden.
- **Partial lines.** The reader only commits a line (and advances the offset) on a trailing
  newline; a half-written final line waits for the next read.
- **Rotation.** On rotation the reader follows by identity (inode), finishes the old file, then
  picks up the new one at offset 0 — the offset checkpoint is `(file-id, byte-offset)`.
- **Backpressure.** Decoupled: if the reader lags, the file grows and the reader catches up;
  `eslogger` never blocks on the reader. The lag is observable (offset vs file size) and is
  itself a feed-health signal.

## Scope / open

- **Built:** nothing here. `evaluate_round` and the battery are batch (`list[dict]` in); there
  is no stream reader, no daemon, no workspace store yet. The eslogger→OCSF adapter (step 2 of
  [[ocsf_ingest_normalization]]) is the one piece that exists.
- **Smallest first step:** the reader loop run *by hand* against a live `eslogger` stream
  (per-event Sigma firing only — no window state) to prove the intake. The launchd plists and
  the windowed battery come after the loop does what it should.
- **Feed-liveness wiring:** the reader is where `feed_live` stops being hardcoded — a stalled
  read or a closed pipe is the NONE signal the temporal fold consumes. Wire it once the loop
  exists.
- **The off-switch still applies per-source:** the high-fidelity Windows cred-access fields
  (`CallTrace`, `GrantedAccess`) have no OCSF home, so a streamed source feeding
  fidelity-critical detections runs *native*, not normalized — the reader honors the same
  per-source vocab choice as a batch round.
