import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

writeFileSync(
  fileURLToPath(new URL("./qa-root-control-executed", import.meta.url)),
  "unreviewed root build control executed\n",
);

export default { plugins: [] };
