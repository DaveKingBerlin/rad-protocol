# Blockfall — ADHS 3 Codex Benchmark Result (historical)

This falling-block benchmark was completed autonomously with the ADHS 3
runtime-agnostic core and the generated Codex adapter. The same requirement set
is now published under the neutral example name **Blockfall**.

## Result

- Status: **PASSED**
- ADHS: **3.0.0-alpha.1** benchmark core
- Runtime: **Codex / GPT-5.6 Sol**
- Total runtime: approximately **3h 40m**
- Human interventions: **0**
- Roadmap phases: **6/6 passed**
- Unit tests: **147/147**
- Playwright E2E: **30/30**
- Production-runtime checks: **3/3**
- Documented-start check: **1/1**
- Defects: **4**, all independently CLOSED
- Adversarial findings: **1 accepted and resolved; 0 pending**
- External/provider services: **0**
- Production E2E seam: **absent**
- Generated adapters: **synchronized at final gate**
- Product contract hash: **unchanged during the run**

## Session token usage

Exact Codex session metrics captured after the run:

- Total: **741,942**
- Input: **661,843**
- Cached input: **51,971,712**
- Output: **80,099**
- Reasoning: **32,726**

Cached input was reported separately by Codex and is not included in the
reported `total` value.

## Architecture selected by ADHS

- frontend-only static browser application
- strict TypeScript
- Vite
- Vanilla DOM/CSS Grid
- deterministic game/domain reducer
- state-carried seeded 7-bag PRNG
- explicit logical time
- deterministic bounded wall-kick rules
- atomic line-clear resolution
- deterministic score/level transitions
- project-local Vitest and Playwright Chromium
- validated E2E-only state/time seam, absent from production
- no backend
- no database or durable persistence
- no external/provider services

## ADHS 3 runtime-neutrality evidence

The run completed using:

```text
REQUIREMENTS.md
      +
.adhs/ canonical core
      +
generated Codex adapter
      ↓
complete autonomous delivery
```

At the final gate the adapters were still synchronized and the product contract
hash was unchanged. No canonical-core or adapter override was reported as
necessary during the benchmark.

## Final outcome

```text
PROJECT COMPLETE — ALL ACCEPTANCE CRITERIA PASSED
```
