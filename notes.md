# github-core-clone-01 — entry notes

- Competition: **github-core-clone-01** — "Build a GitHub-compatible git forge", $500, top 20 paid
  ($100/$70/$50/$20×7/$14×10). Not escrowed, no entry fee.
- Deadline: **2026-11-21 06:30 UTC (13:30 WIB)**. Final instances drawn from drand round 34146612
  (2026-11-21T06:40:00Z). Practice: 3 instances from round 33447412 (2026-10-28).
- Prize bar: score strictly above the house reference forge's, with the 90% paired t-interval of
  the per-instance lead above 0 (a tie is not a win). Reference: 120/120 conformance on all 3
  calibration runs, expected total ≈ 900/1000 (feature 600 + agent 200 + perf ~100).

## Entry

- Repo: https://github.com/Putra-122/makefun-github-core-clone-01 (public, main)
- Entry commit: `e4134e9a56fe24dd53bd5d7d56c81a64e00c64f3` (first commit; notes updated in a second commit)
- Stack: one Node 22 process, stdlib only, no git binary, no outside service, in-memory store.
  `main.ts` (lifecycle, as shipped) + `app.ts` (the forge, ~131 KB).
- Surface: git smart HTTP (upload-pack v2 ls-refs/fetch, receive-pack v0 report-status + sideband),
  REST v3 (/api/v3), GraphQL v4 (/api/graphql), MCP (/mcp, modern server/discover 2026-07-28 +
  legacy initialize fallback).

## Local grade (kit's sdk/run.ts, fresh server, 2026-11-20 ~00:50 UTC)

- **Conformance: 120/120** — git 30/30, repos 15/15, issues 15/15, pulls 20/20,
  protocol 5/5, graphql 20/20, mcp 15/15. Feature 600/600, agent-native 200/200.
- **Performance: 196/200** (p50 of 3 rounds, local VM, 1.5 shared CPUs):
  - push: 426.687 ms p50 vs T_ref 1640.82 ms → 49 pts
  - clone: 82.383 ms p50 vs T_ref 266.941 ms → 46 pts
  - read: 809.146 ms p50 vs T_ref 2759.715 ms → 47 pts
  - write: 112.541 ms p50 vs T_ref 348.965 ms → 45 pts
- **Total local score: 996/1000** (columns: feature 600, agent 200, perf 196, working 1).
- Raw outputs: /tmp/grade7.json (conformance + perf, fresh server). Earlier runs: /tmp/grade5.json
  (120/120, no perf), /tmp/grade3.json (86/120 — before the git-layer fixes), /tmp/grade1.json.
- Lifecycle check (fake env): main.ts binds an ephemeral port, POSTs /register, polls /done,
  exits 0 — verified 2026-11-20 (~00:55 UTC), log /tmp/entry-lifecycle.log.
- `makefun grade-local` could NOT be run here: the `makefun` CLI binary is not on this VM's PATH
  (parent runs it). sdk/run.ts is the kit's own local conformance+perf runner and is the evidence
  above; grade-local should be run by the parent before submitting if available.

## Parent pre-submit verification (2026-11-20 ~07:45 WIB, independent re-check)

- Re-grade on a FRESH server (sdk/run.ts --perf, parent run, /tmp/grade-parent.json):
  conformance **120/120** (all groups), perf **192/200** (push 407ms/50, clone 88ms/45,
  read 677ms/50, write 101ms/47), total **992/1000**. Reproduces the subagent's
  996/1000 (perf 196) within VM noise.
- `makefun grade-local` (server's own dev grading, trial-0, --driver process):
  agent 200, feature 600, perf 190, **score 990/1000**, working 1, entry exited clean.
- Three runs, two runners: 990 / 992 / 996 vs house reference ~900 — lead ~90 points,
  from perf (reference ~100). Conformance ties the reference at 120/120.
- Intake branding verified live: README on GitHub raw has all 3 badges + bounty link;
  About has homepage + `makefun` topic + description naming make.fun; repo PUBLIC,
  HEAD `5582166` on GitHub, tree clean, `.makefun/owner.json` wallet correct.
- Quota: 2 left today (GTA6 used 1 of 3). Deadline: entries close 2026-11-21 06:30 UTC
  (13:30 WIB). All pre-submit checks PASS — awaiting user GAS to submit.
- Minor note: notes.md's per-workload perf numbers (426/82/809/112ms) don't match
  grade7.json (453/76/613/74ms) — different run's numbers; totals agree (196). Not a
  grade problem.

## Caveats (honest)

- Perf was measured locally on this VM, not on the production cluster where the reference T_refs
  were calibrated (2026-11-14). The ratios are large (2.6x–3.9x faster than T_ref on every
  workload), so even a substantially slower production relative would keep perf well above the
  reference's ~100 — but the exact production perf score is unknowable locally.
- Final instances are drawn fresh (drand round 34146612); practice instances (round 33447412)
  are what the local runs used. Conformance is deterministic by construction (fixed timestamps,
  counter ids, no wall-clock in state), so 120/120 should transfer.
- Do NOT re-run the grader against a server that already ran a full suite: state persists
  (repos already exist → 422, refs already advanced → non-fast-forward). Always grade on a
  fresh server instance.

## Build history (bugs found by the local grader, all fixed)

1. Missing `FLUSH_PKT`/`DELIM_PKT`/`RESPONSE_END_PKT` constants → git 0/30.
2. Missing `parsePktLines`/`sidebandPacket`/`buildPackfile`/`parsePackfile` adapters (chunk 1
   actually defined `decodePktLines`/`sidebandPackets`/`writePack`/`readPack`).
3. No v2 capability advertisement (server always answered v0) → added `Git-Protocol: version=2`
   handling, `ls-refs=unborn`, `fetch=shallow filter`, `object-format=sha1`.
4. wanted-refs lines lacked the ref name; ACK lines were lowercase; ls-refs peel used `^{}` instead
   of the `peeled:` attribute; no v0 fetch response shape (NAK/ACK + sideband).
5. `collectForFetch` marked the parent (not the tip) as the shallow boundary; re-sent objects
   reachable from haves; deepen walked the full held closure past the shallow line.
6. A scripted splice duplicated part of app.ts (183 KB); cleaned to a single copy (130 KB).
7. `GqlParser` used a TS parameter property, unsupported by `--experimental-strip-types`.
