# RAD Protocol Benchmarks

This file records observed results from real proof-of-concept runs.

These are **case studies, not universal performance guarantees**. Runtime, model,
token usage, test counts, cost and wall-clock duration depend on requirements,
permissions, provider/runtime behavior, machine performance and project
complexity.

## Public/reproducible examples

| Project | Protocol | Agent runtime / model | Wall-clock | Human intervention | Phases | Unit/domain/app | E2E | Defects | Result |
|---|---|---|---:|---|---:|---:|---:|---:|---|
| Snake | ADHS v2 | Codex | ~3h 10m | 0 | 7/7 | 229/229 | 10/10 | 12 closed | PASSED |
| Paddle Duel | ADHS v2.1 | Codex | ~2h 50m | 0 | 6/6 | 160/160 | 36/36 | 2 closed | PASSED |
| Blockfall | ADHS 3 alpha core | Codex / GPT-5.6 Sol | ~3h 40m | 0 | 6/6 | 147/147 | 30/30 | 4 closed | PASSED |
| Blockfall | ADHS 3 alpha core | OpenCode 1.18.15 / DeepSeek V4 Flash Latest | ~8h | several permission stops; exact count not recorded | 8/8 | 175/175 (128 domain + 47 app) | 15/15 | 5 closed | PASSED |

The two Blockfall runs used the runtime-independent 3.x architecture before the
final RAD Protocol rename. Their results are retained as cross-runtime evidence.

## Runtime and cost metrics

| Project/runtime | Agent/orchestrator active time | Provider activity | Cost | Cost type |
|---|---:|---:|---:|---|
| Blockfall / Codex | not separated from observed run | Codex tokens: 741,942 total; 51,971,712 cached input reported separately | ~$31.70 previously estimated API-equivalent | estimate, not actual user charge |
| Blockfall / OpenCode | Orchestrator: ~1h 21m | 1,304 OpenRouter requests; adjusted summed `generation_time_ms`: ~7h 48m | **$2.34** | actual provider charge |

OpenRouter raw summed generation time was 10h 33m 34.4s. One apparent
stalled/interrupted request accounted for 2h 45m 16.2s; excluding it yields
7h 48m 18.2s. Summed request time is not wall-clock time because requests may
overlap and local tool/permission waits are represented differently.

## Codex token metrics

Cached input is reported separately and is not included in the `total` value
shown by Codex in the observed sessions.

| Project | Total | Input | Cached input | Output | Reasoning |
|---|---:|---:|---:|---:|---:|
| Snake | not recorded | not recorded | not recorded | not recorded | not recorded |
| Paddle Duel | 481,023 | 419,362 | 28,841,216 | 61,661 | 21,240 |
| Blockfall | 741,942 | 661,843 | 51,971,712 | 80,099 | 32,726 |

## Blockfall runtime-neutrality findings

Codex and OpenCode both completed the same Blockfall contract without a
runtime-specific product/core fork. For the clean OpenCode product run:

- canonical core overrides required: **0**
- manual `.opencode/` adapter edits required: **0**
- generic harness fixes discovered before the clean product run: **2**
  - CRLF/LF-normalized adapter-core hashing
  - Windows test-process cleanup metadata schema

The OpenCode run also exposed a scheduler lifecycle defect and a naming-compliance
issue that were independently validated and incorporated into alpha.3 hardening.

See `examples/blockfall/RESULT_CODEX.md` and
`examples/blockfall/RESULT_OPENCODE.md`.

## Runtime matrix

Run the exact same Blockfall requirements and canonical `.rad/` core through:

- Codex ✅ (pre-RAD rename core)
- OpenCode ✅ (pre-RAD rename core)
- Claude Code — pending
- Cursor — pending

See `docs/BLOCKFALL_RUNTIME_MATRIX_TEST.md`.
