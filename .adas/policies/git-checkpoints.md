# Policy: Git Checkpoints and Resumability

After each passed phase leave a coherent checkpointable state.

If the runtime is allowed to commit, use a clear phase-oriented commit. If it is
not, report the exact recommended commit and ensure `git status` is coherent.

Never rewrite history during an autonomous delivery run.
Never commit ignored runtime artifacts.

After interruption, reconstruct state from Git, ledgers, reports, tests and the
working tree. Do not redo accepted implementation blindly.
