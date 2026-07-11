import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";

const outfile = join(tmpdir(), `identity-broker-${Date.now()}-${Math.random().toString(16).slice(2)}.js`);

try {
  await build({
    entryPoints: ["src/index.ts"],
    format: "esm",
    target: "es2022",
    outfile,
    logLevel: "silent",
  });

  const [expected, actual] = await Promise.all([
    readFile(outfile, "utf8"),
    readFile("src/index.js", "utf8"),
  ]);

  if (expected !== actual) {
    console.error("src/index.js is out of date. Run npm run build and commit the generated file.");
    process.exitCode = 1;
  }
} finally {
  await rm(outfile, { force: true });
}
