# Rename to RAD Protocol

Starting with **3.0.0-alpha.3**, the project is named:

**RAD Protocol — Runtime-Agnostic Delivery Protocol**

The public prerelease name before alpha.3 was **ADHS — Autonomous Development
Hyperautomation System**. During alpha.3 preparation, **ADAS — Autonomous
Development Automation System** was briefly considered as an intermediate name
but was not retained as the canonical release identity.

Because 3.0 is still prerelease, alpha.3 makes the canonical rename directly:

| Before | 3.0.0-alpha.3+ |
|---|---|
| ADHS / intermediate ADAS | RAD Protocol |
| `.adhs/` / intermediate `.adas/` | `.rad/` |
| `adhs_version` / intermediate `adas_version` | `rad_version` |
| `/adhs-*` / intermediate `/adas-*` commands | `/rad-*` commands |

Generated runtime adapters must be regenerated after applying the rename.
Historical benchmark result files may still mention ADHS when describing runs
that actually occurred before alpha.3.
