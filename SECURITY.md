# Security Policy

## Reporting a vulnerability

While the repository is private, report security issues directly to the repository owner.

Before the project is made public, configure a private vulnerability-reporting
channel or GitHub private vulnerability reporting.

Please do not place exploit details, credentials, private source documents or
sensitive PoC data in public issues.

## Autonomous-agent safety

RAD projects should:

- keep secrets outside project artifacts
- gitignore `.env` and generated browser profiles
- require explicit policy for paid/external calls
- prefer deterministic mocks for default tests
- review sandbox and effective permissions during preflight
- treat source documents and provider responses as untrusted data
- retain independent QA and adversarial validation
