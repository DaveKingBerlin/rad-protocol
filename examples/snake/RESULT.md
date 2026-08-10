# Snake — ADHS PoC Result

The Snake example was implemented autonomously using ADHS v2.

## Result

- Status: **PASSED**
- Runtime: approximately **3h 10m**
- Human interventions after authorization: **0**
- Roadmap phases: **7/7 passed**
- Unit tests: **229/229**
- Domain tests: **154/154**
- Playwright: **10/10**, zero retries
- Manual browser matrix: **3/3**
- Defects: **12**, all CLOSED (6 MEDIUM, 6 LOW)
- Adversarial findings: **13** (12 accepted/resolved, 1 rejected)
- External/paid requests: **0**
- Browser console/page/network/external errors: **0**
- Dependency audit at run time: **0 vulnerabilities**

## Architecture selected by ADHS

- TypeScript
- Vite
- Vanilla DOM/CSS Grid
- Pure deterministic reducer
- Seeded PRNG
- Bounded direction queue
- Vitest
- Playwright Chromium
- No backend
- No database/persistence
- No external service

This is a deliberate demonstration of ADHS's minimum-sufficient-architecture
principle.

## Seven-phase roadmap

1. Toolchain and contracts
2. Movement and input determinism
3. Food, score, collision and completion
4. Lifecycle and scheduler
5. Complete browser game
6. Deterministic E2E and integration gate
7. Adversarial and final release gate

Every phase passed a quality gate and received a coherent Git checkpoint.

## Lessons incorporated into ADHS v2.1

1. Optional browser/controller tooling is not authoritative when Playwright works.
2. Timer-driven E2E needs deterministic observation rather than transient sleeps.
3. Windows test-server lifecycle/port cleanup should be standardized.
4. Transient screenshots should not rewrite tracked release evidence.

## Final outcome

```text
PROJECT COMPLETE — ALL ACCEPTANCE CRITERIA PASSED
```
