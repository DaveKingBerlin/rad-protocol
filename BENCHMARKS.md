# ADAS Benchmarks

This file records observed results from real ADAS/legacy-ADHS proof-of-concept
runs. These are **case studies, not universal performance guarantees**.

## Public/reproducible examples

| Project | Framework | Agent runtime | Scope | Wall-clock | Human intervention | Phases | Unit/domain/app | E2E | Defects | Cost | Cost type | Result |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---|---|
| Snake | legacy ADHS v2 | Codex | Small deterministic browser game | ~3h 10m | 0 | 7/7 | 229/229 | 10/10 | 12 closed | not recorded | — | PASSED |
| Paddle Duel | legacy ADHS v2.1 | Codex | Real-time two-player paddle game | ~2h 50m | 0 | 6/6 | 160/160 | 36/36 | 2 closed | not recorded | — | PASSED |
| Blockfall | legacy ADHS 3.0.0-alpha.1 | Codex / GPT-5.6 Sol | Deterministic falling-block puzzle | ~3h 40m | 0 | 6/6 | 147/147 | 30/30 | 4 closed | ~$31.70 | API-equivalent estimate, not actual charge | PASSED |
| Blockfall | legacy ADHS 3.0.0-alpha.2 | OpenCode 1.18.15 / DeepSeek V4 Flash Latest | Same deterministic falling-block contract | ~8h | several permission stops | 8/8 | 175/175 | 15/15 | 5 closed | **$2.34** | actual provider charge reported | PASSED |

## Timing metrics

Wall-clock, agent-reported active time, provider request-generation time and
permission/blocking time are different metrics and must not be conflated.

For future runtime-matrix runs record, when available:

- wall-clock elapsed
- total agent/runtime active time
- orchestrator active time
- summed provider generation time
- pause/blocked time
- number of human interventions
- number of permission interruptions
- quota interruptions
- provider cost and cost type

### OpenCode Blockfall timing

- wall-clock elapsed: ~8h
- orchestrator-reported active time: ~1h 21m
- OpenRouter requests: 1,304
- summed `generation_time_ms` raw: 10h 33m 34.4s
- abnormal single request: 2h 45m 16.2s
- summed request generation time excluding that outlier: 7h 48m 18.2s
- permission interruptions: several; exact count not recorded
- actual provider charge reported: $2.34

## Token metrics

Token values are copied from exact runtime-reported session metrics when available.
Cached input is reported separately and is not included in the `total` value shown
by Codex in the observed sessions.

| Project / run | Total | Input | Cached input | Output | Reasoning |
|---|---:|---:|---:|---:|---:|
| Snake / Codex | not recorded | not recorded | not recorded | not recorded | not recorded |
| Paddle Duel / Codex | 481,023 | 419,362 | 28,841,216 | 61,661 | 21,240 |
| Blockfall / Codex | 741,942 | 661,843 | 51,971,712 | 80,099 | 32,726 |
| Blockfall / OpenCode | not recorded in benchmark summary | — | — | — | — |

## Runtime matrix

Run the exact same Blockfall requirements and canonical core through:

- Codex ✅
- OpenCode ✅
- Claude Code
- Cursor

The Codex and OpenCode passes occurred before the ADAS alpha.3 rename. Alpha.3
retains their benchmark results while changing the framework name and canonical
folder from `.adhs/` to `.adas/`.

See `docs/BLOCKFALL_RUNTIME_MATRIX_TEST.md` and the per-runtime result files under
`examples/blockfall/`.
