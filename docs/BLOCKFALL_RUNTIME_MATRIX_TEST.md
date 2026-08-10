# ADAS 3 Blockfall Runtime-Matrix Test

Use `examples/blockfall/REQUIREMENTS.md` as a reproducible cross-runtime benchmark.

Blockfall is a deterministic falling-block puzzle benchmark with seven tetromino
shapes, rotations, bounded wall kicks, line clearing, scoring, levels and
controlled time/randomness.

## Prepare a fresh project

Copy the ADAS 3 template, then:

```text
copy examples/blockfall/REQUIREMENTS.md REQUIREMENTS.md
python tools/generate_adapters.py --check --all
```

Initialize a fresh Git baseline before product code.

## Per runtime

Run the same canonical sequence:

1. ADAS preflight
2. ADAS architecture audit
3. resolve only A-class blocking decisions
4. autonomous implementation
5. final release gate

Record runtime/version, provider/model, wall-clock elapsed, agent/orchestrator
active time when exposed, provider request-generation time when available, human
interventions, permission interruptions, test counts, defects, adversarial
findings, token/usage data, cost/cost type and adapter-specific limitations.

During the runtime matrix, keep the same canonical `.adas/` core and the same
`REQUIREMENTS.md`. Runtime-specific manual adapter edits should be recorded as a
benchmark failure or limitation, not silently folded into the core.

The product result should be judged against the same `REQUIREMENTS.md`, not against
runtime-specific convenience features.

## Current matrix

- Codex / GPT-5.6 Sol: **PASSED** on pre-rename alpha core
- OpenCode 1.18.15 / DeepSeek V4 Flash Latest: **PASSED** on pre-rename alpha core
- Claude Code: pending
- Cursor: pending

For alpha.3 and later runs, use `.adas/` as the canonical source of truth.
