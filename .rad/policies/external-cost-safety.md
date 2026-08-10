# Policy: External Calls, Cost and Secrets

Unless `REQUIREMENTS.md` and an accepted product decision explicitly permit a
live external action:

- default development/test runs perform zero paid AI/provider requests
- use deterministic mocks, fake servers or injected transports
- live smoke tests are opt-in
- never silently fall back from local/private to paid/cloud execution
- never commit secrets, auth tokens, private source data or generated browser profiles
- external/destructive/costly actions require the approval boundary defined by the product/runtime
