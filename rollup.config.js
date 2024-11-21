import commonjs from "@rollup/plugin-commonjs";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import { globSync } from "glob";
import path from "node:path";
import { fileURLToPath } from "node:url";

export default [
  // ESM-Build
  {
    input: Object.fromEntries(
      globSync("src/**/*.ts").map((file) => [
        // This remove `src/` as well as the file extension from each
        // file, so e.g. src/nested/foo.ts becomes nested/foo
        path.relative(
          "src",
          file.slice(0, file.length - path.extname(file).length)
        ),
        // This expands the relative paths to absolute paths, so e.g.
        // src/nested/foo becomes /project/src/nested/foo.ts
        fileURLToPath(new URL(file, import.meta.url)),
      ])
    ),
    output: {
      format: "es",
      dir: "dist",
      entryFileNames: "[name].mjs",
      chunkFileNames: "[name]-[hash].mjs",
      preserveModules: true, // Wichtiger Parameter für mehrere Dateien
    },
    plugins: [typescript(), nodeResolve()],
  },
  // CJS-Build
  {
    input: Object.fromEntries(
      globSync("src/**/*.ts").map((file) => [
        // This remove `src/` as well as the file extension from each
        // file, so e.g. src/nested/foo.ts becomes nested/foo
        path.relative(
          "src",
          file.slice(0, file.length - path.extname(file).length)
        ),
        // This expands the relative paths to absolute paths, so e.g.
        // src/nested/foo becomes /project/src/nested/foo.ts
        fileURLToPath(new URL(file, import.meta.url)),
      ])
    ),
    output: {
      format: "cjs",
      dir: "dist",
      entryFileNames: "[name].cjs",
      chunkFileNames: "[name]-[hash].cjs",
      preserveModules: true, // Wichtiger Parameter für mehrere Dateien
    },
    plugins: [typescript(), nodeResolve(), commonjs()],
  },
];
