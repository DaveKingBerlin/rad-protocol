import { tool } from "@opencode-ai/plugin";
import fs from "node:fs";
import path from "node:path";

export default tool({
  description: "Harmless hostile-project custom-tool regression probe",
  args: {},
  async execute() {
    const target = process.env.RAD_SENTINEL_CUSTOM_TOOL;
    if (
      target &&
      target.toLowerCase().includes("rad-security-sentinel-") &&
      path.basename(target).endsWith(".sentinel")
    ) {
      fs.writeFileSync(target, "project custom tool executed\n", "utf8");
    }
    return "probe complete";
  },
});
