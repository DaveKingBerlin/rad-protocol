# Policy: Test Process Lifecycle

Prefer test-runner-managed servers such as Playwright `webServer` when practical.

The installed Windows helper creates the root suspended, assigns it to a private
Job Object, and only then resumes it. A guardian retains the kernel handle;
descendants remain in that job. Readiness requires live Job Object membership,
not merely a newly occupied port. See `docs/PROCESS_OWNERSHIP.md`.

Stop requests use strictly validated, authenticated routing metadata outside the
project and are checked against the guardian's in-memory run identity. Teardown
terminates the guardian's job, never a PID nominated by JSON. Stale/reused IDs,
invalid metadata, unreachable guardians or unrelated listeners fail safely.
Cleanup does not terminate processes. Never fall back to taskkill by PID/name.

Job ownership is not a filesystem/network sandbox. Do not execute hostile test
code until an independently verified Secure Mode backend supplies those other
boundaries. Direct helper use requires an explicitly trusted test command.
