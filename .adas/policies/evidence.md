# Policy: Evidence

Use evidence appropriate to the requirement: unit/integration/E2E output,
browser/product observations, persistence/restart checks, security checks,
curated screenshots or other measurable proof.

Transient output belongs under ignored paths such as:

- `e2e/artifacts/`
- `screenshots/generated/`

Durable evidence belongs under:

- `screenshots/evidence/`
- explicit release/requirement reports

Do not rewrite tracked evidence on every test run. Promote only meaningful
release/defect evidence.

For web products, project-local Playwright Chromium is the default authoritative
browser validator unless the product contract selects another platform.
Optional browser-agent integrations may supplement validation but must not block
release when authoritative validation works.
