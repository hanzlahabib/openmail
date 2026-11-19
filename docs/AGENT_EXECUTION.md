# Agent execution ledger

Only work that is actually recorded here happened. The 50-role table in the master prompt is a
set of workstreams, not a headcount: dependent work is serialized and roles are merged into the
agents below. Agents run in isolated git worktrees on branches `wave1-<area>`; the orchestrator
merges after review. Nothing is pushed anywhere.

| Wave | Agent / branch | Owns (roles) | Files owned | Status |
|---|---|---|---|---|
| 0 | orchestrator (main) | 01 architecture, 20 config | workspace, `openmail-core` | done, committed |
