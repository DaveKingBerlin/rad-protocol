# Paddle Duel — ADHS PoC Result

This paddle-and-ball benchmark was implemented autonomously using ADHS v2.1 and is now published as the Paddle Duel example.

## Result

- Status: **PASSED**
- Total runtime: approximately **2h 50m**
- Human interventions after authorization: **0**
- Roadmap phases: **6/6 passed**
- Unit/domain/frontend tests: **160/160**
- Playwright Chromium: **36/36**
- Retries/skips/failures: **0/0/0**
- Defects: **2**, all CLOSED
  - 1 MEDIUM
  - 1 LOW
- Adversarial findings: **4**
  - 2 accepted into closed defects
  - 2 rejected with documented out-of-contract rationale
- Final hostile review findings: **0**
- Long-run hostile validation: **3,000,000 deterministic ticks**
- External/paid requests: **0**
- Runtime dependencies: **0**
- Console/page/network/external errors: **0**

## Session token usage

Exact Codex `/status` metrics captured after the run:

- Total: **481,023**
- Input: **419,362**
- Cached input: **28,841,216**
- Output: **61,661**
- Reasoning: **21,240**

The Codex `total` value equals input + output in this observed session; cached
input was reported separately.

## Architecture selected by ADHS

- static Vanilla TypeScript application
- semantic HTML/CSS and direct DOM rendering
- pure deterministic 1/120-second fixed-step game engine
- state-carried seeded randomness
- swept collision detection
- exactly-once scoring
- deterministic serves
- state-based simultaneous keyboard input
- compile-time E2E-only manual-tick adapter
- Vite / Vitest / Playwright Chromium
- no backend
- no database or persistence
- no routing framework
- no provider/worker/cloud service
- no production runtime dependency

## Delivery workflow

The accepted six-phase roadmap was:

1. Foundation and contracts
2. Deterministic lifecycle/input kernel
3. Collision, scoring, serve and victory
4. Complete browser product
5. Race and resilience hardening
6. Final release gate

Every phase passed and received a coherent Git checkpoint.

## Main lessons

1. The minimum-architecture audit prevented overbuilding.
2. Deterministic manual-tick E2E seams eliminated sleep-based physics assertions.
3. Exact process/PID ownership is important for reliable Windows Playwright teardown.
4. Keyboard tests must deliberately establish and validate focus/blur behavior.
5. Optional browser-plugin incompatibility should remain a warning when Playwright is authoritative.
6. Token counters are useful benchmark metadata and should be captured when available.

## Final outcome

```text
PROJECT COMPLETE — ALL ACCEPTANCE CRITERIA PASSED
```
