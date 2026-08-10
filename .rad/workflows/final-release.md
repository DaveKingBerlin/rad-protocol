# Workflow: Final Release Gate

Run the complete release validation required by `REQUIREMENTS.md` and the accepted
architecture plan.

At minimum where applicable:

- complete unit/integration/contract/security suites
- coverage targets explicitly required/accepted
- full cumulative E2E/product suite
- real browser/manual workflows
- restart/persistence checks
- required themes/viewports/accessibility paths
- console/page/network/runtime error collection
- long final adversarial review
- defect loop for every accepted finding
- post-fix full regression
- criterion-by-criterion final evidence matrix
- generated-adapter drift check
- immutable product-contract check
- public naming compliance audit under `.rad/policies/public-naming.md`

No blocking OPEN/FIX-READY/DISPUTED defect and no PENDING adversarial finding may
remain at successful release.

Tests alone are insufficient when the contract requires manual, visual,
persistence, security, naming or adversarial evidence.
