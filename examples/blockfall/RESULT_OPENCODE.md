# Blockfall — OpenCode Runtime-Matrix Benchmark Result

This benchmark was executed on the 3.0.0-alpha.2 runtime-agnostic core before the
framework rename from **ADHS** to **ADAS** in alpha.3. It used the generated
OpenCode primary orchestrator and delegated agents.

## Result

- Status: **PASSED**
- Benchmark core: **ADHS 3.0.0-alpha.2** (pre-rename)
- Runtime: **OpenCode 1.18.15**
- Provider/model: **OpenRouter / DeepSeek V4 Flash Latest**
- Reasoning profile: **high**
- Wall-clock elapsed: approximately **8h**
- Orchestrator-reported active time: approximately **1h 21m**
- Human intervention: **required for several permission-related stops**; exact count not recorded
- Roadmap phases: **8/8 passed**
- Domain unit tests: **128/128**
- App unit tests: **47/47**
- Playwright E2E: **15/15**
- Production build: **green**
- Defects: **5**, all independently CLOSED
- Adversarial findings: **0 pending** at final gate
- Console/page errors: **0**
- Production test-only seam: **absent**
- Generated adapter drift: **clean** at final gate
- Final release commit: **8081297**
- Actual provider charge reported for the run: **$2.34**

## OpenRouter activity timing

The exported activity contained **1,304 requests**. Summing
`generation_time_ms` yielded **10h 33m 34.4s**. One abnormal request accounted for
**2h 45m 16.2s** with only 23 completion tokens and no normal finish reason.
Excluding that apparent stalled/interrupted outlier yields **7h 48m 18.2s** of
summed request generation time.

Summed request time is not the same as wall-clock time because requests may
overlap and local tool/test/permission waiting is not represented equivalently.

## Final defect finding

The final MEDIUM defect exposed a scheduler lifecycle race: restart did not reset
the fall cadence because a stale timer remained armed. The implementation was
changed so scheduler start cancels the stale timer before re-arming. QA
independently retested and closed the defect.

## Naming audit

The final naming audit removed branded shorthand that the model had reintroduced
in tests/review artifacts. The product code, tests, documentation, screenshots,
test titles, evidence and built output finished with zero unexpected prohibited
name occurrences. The audit instruction itself was the documented declaration
exception.

This finding motivated the canonical ADAS public-naming policy added in alpha.3.

## Runtime-neutrality evidence

For the clean product run:

- canonical core overrides required: **0**
- manual `.opencode/` adapter edits required: **0**
- generic harness fixes discovered before the clean product run: **2**
  - CRLF/LF-normalized adapter-core hashing
  - test-process cleanup metadata schema (`owned_pids` / `root_pid`)

The run therefore validated the generated OpenCode adapter against the same
Blockfall contract without requiring a runtime-specific product/core fork.
