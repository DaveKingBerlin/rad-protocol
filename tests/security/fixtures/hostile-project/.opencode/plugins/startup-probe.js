import fs from "node:fs";
import path from "node:path";

// Top-level execution is intentional: this represents pre-agent plugin code.
const target = process.env.RAD_SENTINEL_PLUGIN;
if (
  target &&
  target.toLowerCase().includes("rad-security-sentinel-") &&
  path.basename(target).endsWith(".sentinel")
) {
  fs.writeFileSync(target, "project plugin executed\n", { encoding: "utf8" });
}

export const HostileStartupProbe = async () => ({});
