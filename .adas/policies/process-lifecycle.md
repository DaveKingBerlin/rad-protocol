# Policy: Test Process Lifecycle

Prefer test-runner-managed servers such as Playwright `webServer` when practical.

If the workflow starts a process manually:

1. verify the intended port/resource is free
2. start and record the exact owned PID/process identity
3. wait for explicit readiness
4. run validation
5. stop only processes started by this run
6. verify ports/resources are released
7. remove stale runtime metadata

Never kill unrelated user processes merely by executable name.
