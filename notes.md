# github-core-clone-01 — rebuild (v2) notes

Rebuilt from scratch in a fresh recorded session after the v1 submit was
rejected server-side (`thinking_reproduces`: the v1 build session had been
compacted, so the server could not see the code being written). No file under
`~/workspace/makefun/entry-github-core-clone/` was read, opened, diffed or
grepped at any point; only the kit was read. All code in `app.ts` / `main.ts`
was written in this session from the kit spec.

## What it is

One Node 22+ process, stdlib only, in-memory. `app.ts` (createApp) + `main.ts`
(env register/done lifecycle). Implements:

- git smart HTTP: upload-pack v2 (ls-refs, fetch, shallow/deepen, wanted-refs,
  sideband packfile) + receive-pack v0 (report-status, non-fast-forward per-ref)
- REST v3: repos, branches, commits, contents, labels, issues, pulls (squash merge)
- GraphQL v4: hand-rolled parser/executor, opaque global ids, cursor pagination,
  introspection, batched documents, mutations
- MCP: server/discover (2026-07-28) + legacy initialize, 8 tools, JSON-RPC errors

Viewer login is the scenario viewer `adaiversen` (id 1000), derived from the
kit's fixed scenario seed.

## Local grade

Command (fresh server each run; state persists in a used server):

```sh
MAKEFUN_SHOP_TOKEN=localcheck node /tmp/launch-entry.mjs  # launcher in /tmp, listens 127.0.0.1:18099
node --experimental-strip-types sdk/run.ts --url http://127.0.0.1:18099 --token localcheck --perf --json
```

Results (kit `sdk/run.ts`, `--driver process` equivalent):

- 2026-11-20 run 1: **991/1000** — feature 600 (120/120), agent 200 (15/15), perf 191
- 2026-11-20 run 2: **992/1000** — feature 600 (120/120), agent 200 (15/15), perf 192
  (push 50, clone 47, read 50, write 45)

Reference forge is ~900. Grade JSONs: `/tmp/grade7.json`, `/tmp/grade8.json`.

## Status

NOT committed, NOT pushed. Ready for the parent to copy into the entry repo,
commit + push, re-bundle and resubmit before entries close 2026-11-21 06:30 UTC.
