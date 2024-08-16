import dts from "bun-plugin-dts";
import Logger from "@rabbit-company/logger";
import fs from "fs/promises";

await fs.rm("./browser", { recursive: true, force: true });
await fs.rm("./module", { recursive: true, force: true });
await fs.rm("./dist", { recursive: true, force: true });

Logger.info("Start bulding browser...");
let browserBuild = await Bun.build({
	entrypoints: ["./src/argon2id.ts", "./src/argon2id_worker.ts"],
	outdir: "./browser",
	target: "browser",
	format: "esm",
	minify: {
		identifiers: false,
		syntax: true,
		whitespace: true,
	},
	plugins: [],
});

await Bun.write(Bun.file("./browser/argon2id_wasm_bg.wasm"), Bun.file("./src/argon2id_wasm_bg.wasm"));

if (browserBuild.success) {
	Logger.info("Bulding browser complete");
} else {
	Logger.error("Bulding browser failed");
}

Logger.info("Start bulding module...");
let moduleBuild = await Bun.build({
	entrypoints: ["./src/argon2id.ts", "./src/argon2id_worker.ts"],
	outdir: "./module",
	target: "browser",
	format: "esm",
	minify: false,
	plugins: [dts({ output: { noBanner: true } })],
});

await Bun.write(Bun.file("./module/argon2id_wasm_bg.wasm"), Bun.file("./src/argon2id_wasm_bg.wasm"));

if (moduleBuild.success) {
	Logger.info("Bulding module complete");
} else {
	Logger.error("Bulding module failed");
}

fs.cp("./src/index.html", "./dist/index.html", { recursive: true, force: true });

Logger.info("Start bundling dist...");
let distBuild = await Bun.build({
	entrypoints: ["./src/index.ts", "./src/argon2id_worker.ts"],
	outdir: "./dist",
	target: "browser",
	format: "esm",
	minify: true,
	sourcemap: "none",
	plugins: [],
});

await Bun.write(Bun.file("./dist/argon2id_wasm_bg.wasm"), Bun.file("./src/argon2id_wasm_bg.wasm"));
await Bun.write(Bun.file("./dist/index.html"), Bun.file("./src/index.html"));

if (distBuild.success) {
	Logger.info("Bundling dist complete");
} else {
	Logger.error("Bundling dist failed");
	Logger.error(distBuild.logs);
}
