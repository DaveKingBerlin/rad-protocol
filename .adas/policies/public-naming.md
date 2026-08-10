# Policy: Public Naming Compliance

Public product/example terminology in `REQUIREMENTS.md` is part of the product
contract. If the requirements deliberately use a neutral name or explicitly ban
third-party branded shorthand, agents must preserve that terminology throughout
the delivery lifecycle.

Rules:

1. Do not reintroduce third-party product or brand names as shorthand in product
   code, tests, comments, fixtures, screenshots, evidence, release notes, test
   titles, generated production artifacts, or user-facing copy.
2. Prefer neutral domain terminology for mechanics, states, test cases and score
   labels.
3. A third-party term may appear in the policy/instruction that declares it
   prohibited when that declaration is necessary; that declaration is the only
   allowed exception unless `REQUIREMENTS.md` explicitly permits another one.
4. Before final release, perform a case-insensitive repository-wide naming audit
   over relevant product, test, documentation, evidence and built-artifact paths.
5. Any unexpected prohibited-name occurrence is a release blocker until removed
   and affected validation is rerun.

Naming cleanup must not change mechanics or acceptance criteria merely to avoid a
term.
