# RAD Test Process Ownership

RAD's Windows test harness terminates processes only through a Windows Job
Object created for one test run. It never sends a termination request to a PID
read from JSON, and it never infers ownership from a port, executable name, or
parent/child snapshot.

## Trusted components

`security/rad_security/processes.py` is part of the installed, release-pinned
RAD security launcher. In secure mode, the PowerShell wrappers require absolute
paths in `RAD_TRUSTED_PROCESS_HELPER` and `RAD_TRUSTED_PYTHON`; both paths must
be outside the untrusted project. Resolving a same-named helper or interpreter
through the project's current directory or `PATH` is intentionally unsupported.

Process control state and `process-control.key` live in the runtime-owned state
directory, outside the project. The installed launcher must restrict that
directory from untrusted project processes. The key authenticates the state
record; it is not stored in project metadata.

## Start and stop protocol

The guardian creates the command processor suspended, assigns it to a new Job
Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and resumes it only
after assignment succeeds. Descendants inherit Job membership. If assignment
fails, the newly created suspended process is terminated before it can execute.

Readiness requires a listener on the requested port whose live process handle
is confirmed by `IsProcessInJob` to belong to that guardian's Job Object. An
unrelated listener can prevent startup but can never become owned.

Teardown validates all of the following before contacting the guardian:

- strict JSON schema, including rejection of duplicate or unexpected keys;
- HMAC authentication using the external process-control key;
- canonical project identity and requested port;
- run identity and per-run control token;
- guardian PID plus its Windows process-creation identity.

The guardian then validates the request against its in-memory run state and
calls `TerminateJobObject` on its own handle. PIDs in the record are diagnostic
only. If any validation is ambiguous, teardown fails without killing anything.

The cleanup command never terminates processes. It removes only authenticated
records whose guardian creation identity no longer exists. Active, corrupt, or
unauthenticated records are retained for inspection.

## Environment behavior

Managed test commands receive a minimal environment by default: Windows system
locations, temporary-directory locations, `ComSpec`, `PATHEXT`, and a system-only
`PATH`. Additional non-secret values must be passed explicitly with
`--environment NAME=VALUE` (or the PowerShell `-Environment` parameter). This
prevents test commands from automatically inheriting provider, cloud, package,
Git, or SSH credentials.

## Limitations

The current Job Object implementation is Windows-only. It is process ownership,
not a complete filesystem or network sandbox. RAD Secure Mode must combine it
with the launcher's filesystem and network controls. The external state key is
a local trust anchor, not a signed-release authenticity claim; its directory
must be protected by the installed launcher and OS access policy.

