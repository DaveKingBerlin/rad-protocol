# Rename: ADHS → ADAS

Starting with **3.0.0-alpha.3**, the project is named:

**ADAS — Autonomous Development Automation System**

The previous alpha name was **ADHS — Autonomous Development Hyperautomation
System**.

Because 3.0 is still prerelease, alpha.3 makes the canonical rename directly:

| Before | alpha.3+ |
|---|---|
| ADHS | ADAS |
| `.adhs/` | `.adas/` |
| `adhs_version` | `adas_version` |
| `/adhs-*` Cursor command files | `/adas-*` command files |

Generated runtime adapters must be regenerated after applying the rename.
Historical benchmark result files may still mention ADHS when describing runs
that actually occurred before alpha.3.
