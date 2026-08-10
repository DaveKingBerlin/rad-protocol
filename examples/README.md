# ADAS Example Requirements

These examples demonstrate how a product-specific `REQUIREMENTS.md` can be
structured and let users run ADAS on small self-contained projects.

| Example | Complexity | Focus | Verified |
|---|---|---|---|
| [Snake](snake/REQUIREMENTS.md) | Small | deterministic game loop, keyboard input | ✅ [Result](snake/RESULT.md) |
| [Paddle Duel](paddle-duel/REQUIREMENTS.md) | Small–medium | simultaneous input, collision physics | ✅ [Result](paddle-duel/RESULT.md) |
| [Blockfall](blockfall/REQUIREMENTS.md) | Medium | rotations, line clearing, timing | ✅ [Codex](blockfall/RESULT_CODEX.md) / [OpenCode](blockfall/RESULT_OPENCODE.md) |

## Recommended first run

Start with Snake:

```text
Preflight → Architecture Audit → Build → QA → Adversary → Defect Loop → Gate
```

Copy an example to the project root, for example:

```powershell
Copy-Item .\examples\snake\REQUIREMENTS.md .\REQUIREMENTS.md
```

Then generate/check runtime adapters and start the selected runtime:

```powershell
python .\tools\generate_adapters.py --check --all
```

Ask the runtime to:

1. `Run the ADAS preflight.`
2. `Run the ADAS architecture audit.`
3. `Start the ADAS implementation and continue through all approved phases.`

A good requirements file makes vision, non-goals, stable IDs, observable
behavior, domain invariants, edge cases, NFRs, testing, acceptance scenarios and
final success criteria explicit without forcing unnecessary technology choices.

## Example naming

The public examples intentionally use generic descriptive names. Older local
benchmark artifacts may contain earlier working titles; the requirements and
technical benchmark scope are otherwise equivalent.
