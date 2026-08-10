# Policy: Deterministic Testing

When correctness depends on timers, game loops, polling, autosave, debounce,
retries, randomness, background jobs or difficult setup, define a deterministic
control/observation strategy.

Prefer:

```text
action -> exact observable state transition -> assertion
```

over arbitrary sleeps.

A test-only state/time seam is allowed when needed for deterministic setup if it:

- exists only in test/E2E builds
- validates injected state
- exercises real production logic after setup
- does not bypass the security/rule being tested
- is proven absent from production builds

Race/timing tests should begin in the first phase where the behavior exists, not
only at final release.
