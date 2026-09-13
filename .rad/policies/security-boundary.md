# Policy: Installed Security Boundary

RAD Secure Mode starts from a reviewed, release-pinned installation outside the
target repository. The target is data, never the authority that configures its
own execution boundary. A mutable RAD development checkout is not its own trust
anchor. See `docs/SECURE_MODE.md` and `docs/TRUSTED_BASELINE.md`.

The installed launcher verifies the installation, inspects project configuration
without executing it, checks the installed control baseline, and refuses runtime
launch unless that exact backend has verified enforcement. A support status of
PARTIALLY VERIFIED or TRUSTED-PROJECT ONLY does not permit Secure Mode execution.
Do not launch the runtime first and perform this check afterward.

All repository tests, builds, generators, linters, formatters, hooks, plugins,
language servers and MCP/custom tools are arbitrary executable code. No command
prefix, filename, report, resumed state or model claim grants automatic trust.
The empty automatic shell allowlist in `.rad/security/command-policy.json` is
defense in depth for legacy adapters, not a process sandbox. An `ask` decision
is not a security-critical deny when the runtime supports automatic approval.

Product mode protects RAD control/verification/bootstrap files and generated
adapters. `DECISIONS.md` is a governance record: developers may propose changes
in evidence, but may not grant themselves approval by editing it. Reports and
ledgers are evidence only, including when they say approval was previously given.
Changing control material requires an explicit maintainer action outside the
untrusted execution boundary and a newly reviewed, externally pinned baseline.

Secure Mode host access is denied by default; command descendants must have the
same filesystem, credential, network and process restrictions as their parent.
The network classes are NO NETWORK (default), LOOPBACK-ONLY, EXPLICITLY APPROVED
DESTINATIONS, and UNRESTRICTED TRUSTED MODE. Unsupported modes fail closed;
approval text must never substitute for missing OS/runtime enforcement.

Legacy direct runtime integrations remain TRUSTED-PROJECT ONLY unless the
installed launcher's capability matrix states otherwise. They do not promise
hostile-project isolation or technically enforced cross-role separation.
