/**
 * Smoke tests for dsh-guard-hooks pure-Node modules.
 * Run: node test/smoke.mjs   (from package root)
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHmac } from "node:crypto";
import { loadConfig } from "../lib/config.js";
import { compilePattern, compileToolMatcher, matchGlobList } from "../lib/patterns.js";
import { runHook, runEventHooks } from "../lib/engine.js";
import { evaluateRules } from "../lib/features/rules.js";
import { extractPaths, interpolateFilePath } from "../lib/features/format.js";
import { redact } from "../lib/audit.js";
import { signBody } from "../lib/webhook.js";

let passed = 0;
let failed = 0;
const failures = [];

function check(label, fn) {
	return Promise.resolve()
		.then(fn)
		.then(() => {
			passed += 1;
			console.log(`ok   ${label}`);
		})
		.catch((error) => {
			failed += 1;
			failures.push(`${label}: ${error.message}`);
			console.log(`FAIL ${label}: ${error.message}`);
		});
}

/* ---------- config ---------- */

await check("loadConfig merges user + project layers", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-home-"));
	const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-repo-"));
	fs.mkdirSync(path.join(repo, ".git"));
	fs.mkdirSync(path.join(repo, ".dsh"));
	fs.mkdirSync(path.join(repo, "sub"));
	fs.mkdirSync(path.join(home, "audit"), { recursive: true });

	fs.writeFileSync(
		path.join(home, "hooks.yaml"),
		[
			"rules:",
			"  deny:",
			'    - "rm -rf /*"',
			"notify:",
			"  onStop: true",
			"audit:",
			"  enabled: true",
			`  path: ${JSON.stringify(path.join(home, "audit", "a.jsonl"))}`
		].join("\n")
	);
	fs.writeFileSync(
		path.join(repo, ".dsh", "hooks.yaml"),
		[
			"rules:",
			"  deny:",
			'    - "*DROP TABLE*"',
			"notify:",
			"  sound: true"
		].join("\n")
	);

	process.env.DSH_HOME = home;
	const { config, sources } = loadConfig(path.join(repo, "sub"));
	assert.equal(config.notify.onStop, true);
	assert.equal(config.notify.sound, true);
	assert.deepEqual(config.rules.deny, ["rm -rf /*", "*DROP TABLE*"]);
	assert.equal(sources.length, 2);
	assert.ok(config.audit.path.includes("audit"));

	fs.rmSync(home, { recursive: true, force: true });
	fs.rmSync(repo, { recursive: true, force: true });
});

await check("inherit:false drops lower layers", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-home-"));
	const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-repo-"));
	fs.mkdirSync(path.join(repo, ".git"));
	fs.mkdirSync(path.join(repo, ".dsh"), { recursive: true });
	fs.writeFileSync(path.join(home, "hooks.yaml"), "notify:\n  onStop: true\n");
	fs.writeFileSync(path.join(repo, ".dsh", "hooks.yaml"), "inherit: false\nnotify:\n  onStop: false\n");
	process.env.DSH_HOME = home;
	const { config } = loadConfig(repo);
	assert.equal(config.notify.onStop, false);
	fs.rmSync(home, { recursive: true, force: true });
	fs.rmSync(repo, { recursive: true, force: true });
});

await check("rules.ask appends across layers (no silent replacement)", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-home-"));
	const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-repo-"));
	fs.mkdirSync(path.join(repo, ".git"));
	fs.mkdirSync(path.join(repo, ".dsh"), { recursive: true });
	fs.writeFileSync(path.join(home, "hooks.yaml"), 'rules:\n  ask:\n    - "A-user"\n');
	fs.writeFileSync(path.join(repo, ".dsh", "hooks.yaml"), 'rules:\n  ask:\n    - "B-project"\n');
	process.env.DSH_HOME = home;
	const { config } = loadConfig(repo);
	assert.deepEqual(config.rules.ask, ["A-user", "B-project"]);
	fs.rmSync(home, { recursive: true, force: true });
	fs.rmSync(repo, { recursive: true, force: true });
});

await check("broken YAML layer is skipped with warning", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-home-"));
	const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-repo-"));
	fs.mkdirSync(path.join(repo, ".git"), { recursive: true });
	fs.writeFileSync(path.join(home, "hooks.yaml"), "rules: [unclosed\n");
	process.env.DSH_HOME = home;
	const { warnings, config } = loadConfig(repo);
	assert.equal(warnings.length, 1);
	assert.deepEqual(config.rules.deny, []);
	fs.rmSync(home, { recursive: true, force: true });
	fs.rmSync(repo, { recursive: true, force: true });
});

/* ---------- patterns ---------- */

await check("glob and regex rule patterns", () => {
	assert.ok(compilePattern("rm -rf /*")("rm -rf / --no-preserve-root"));
	assert.ok(compilePattern("rm -rf /*")("rm -rf /"));
	assert.ok(!compilePattern("rm -rf /*")("ls -la"));
	assert.ok(compilePattern("/drop table/i")("x DROP TABLE users"));
	assert.ok(!compilePattern("git status")("git status -sb")); // literal pattern is exact
	assert.ok(compilePattern("git status")("git status"));
	assert.ok(compilePattern("git *")("git push origin main"));
	const m = compileToolMatcher("Bash|Pwsh");
	assert.ok(m.matches("Bash") && !m.matches("read"));
	assert.ok(matchGlobList("*.ts, *.md", "src/a.ts") && matchGlobList("*.py", "C:\\x\\y.py") && !matchGlobList("*.py", "a.ts"));
	assert.ok(matchGlobList("*.TS", "video.ts"), "extension matching must be case-insensitive");
});

/* ---------- rules ---------- */

await check("evaluateRules ordering deny > ask > warn > allow", () => {
	const rules = {
		deny: ["rm -rf /*"],
		ask: ["npm publish*"],
		warn: ["git reset --hard*"],
		allow: ["git *"]
	};
	assert.equal(evaluateRules(rules, "rm -rf /").action, "deny");
	assert.equal(evaluateRules(rules, "npm publish").action, "ask");
	assert.equal(evaluateRules(rules, "git reset --hard HEAD~1").action, "warn");
	assert.equal(evaluateRules(rules, "git log").action, "allow");
	assert.equal(evaluateRules(rules, "echo hi").action, "none");
});

/* ---------- engine protocol ---------- */

await check("exit code semantics: 0 pass / 2 block / other error", async () => {
	const ok = await runHook({ command: "exit 0", payload: {} });
	assert.equal(ok.ok, true);
	const block = await runHook({ command: "exit 2", payload: {} });
	assert.equal(block.blocked, true);
	const err = await runHook({ command: "exit 3", payload: {} });
	assert.equal(err.error, true);
	assert.equal(err.blocked, false);
});

await check("stdin payload arrives as JSON", async () => {
	const res = await runHook({
		command: 'node -e "let d=\\"\\";process.stdin.on(\'data\',c=>d+=c).on(\'end\',()=>{if(JSON.parse(d).event===\'PreToolUse\')process.exit(0);else process.exit(1)})"',
		payload: { event: "PreToolUse" }
	});
	assert.equal(res.ok, true);
});

await check("runEventHooks forwards payloadExtra fields to hook stdin", async () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-payload-"));
	const dumper = path.join(tmp, "dump.mjs");
	const outFile = path.join(tmp, "payload.json");
	fs.writeFileSync(dumper, [
		'import fs from "node:fs";',
		'fs.writeFileSync(process.argv[2], fs.readFileSync(0, "utf8"));'
	].join("\n"));
	const command = `"${process.execPath}" "${dumper}" "${outFile}"`;
	const results = await runEventHooks(
		[{ command, matcher: ".*", timeoutMs: 15000, async: false }],
		{
			event: "PreToolUse",
			sessionId: "payload-test",
			cwd: tmp,
			toolName: "write",
			payloadExtra: { tool: "write", input: { file_path: "a.mjs", content: "const a = 1;" } }
		}
	);
	assert.equal(results[0].ok, true);
	const payload = JSON.parse(fs.readFileSync(outFile, "utf8"));
	assert.equal(payload.event, "PreToolUse");
	assert.equal(payload.sessionId, "payload-test");
	assert.equal(payload.tool, "write");
	assert.equal(payload.input.file_path, "a.mjs");
	fs.rmSync(tmp, { recursive: true, force: true });
});
await check("stdout JSON decision overrides exit code", async () => {
	const block = await runHook({
		command: 'node -e "console.log(JSON.stringify({decision:\'block\',reason:\'危险\'}))"',
		payload: {}
	});
	assert.equal(block.blocked, true);
	assert.equal(block.reason, "危险");
});

await check("hookSpecificOutput.permissionDecision deny / ask / allow / additionalContext", async () => {
	const deny = await runHook({
		command: 'node -e "console.log(JSON.stringify({hookSpecificOutput:{hookEventName:\'PreToolUse\',permissionDecision:\'deny\',permissionDecisionReason:\'危险操作\'}}))"',
		payload: {}
	});
	assert.equal(deny.blocked, true);
	assert.equal(deny.ask, false);
	assert.equal(deny.reason, "危险操作");

	const ask = await runHook({
		command: 'node -e "console.log(JSON.stringify({hookSpecificOutput:{hookEventName:\'PreToolUse\',permissionDecision:\'ask\',permissionDecisionReason:\'需人工确认\'}}))"',
		payload: {}
	});
	assert.equal(ask.ask, true);
	assert.equal(ask.blocked, false);
	assert.equal(ask.approved, false);
	assert.equal(ask.reason, "需人工确认");

	const allow = await runHook({
		command: 'node -e "console.log(JSON.stringify({hookSpecificOutput:{hookEventName:\'PreToolUse\',permissionDecision:\'allow\'}}))"',
		payload: {}
	});
	assert.equal(allow.approved, true);
	assert.equal(allow.ok, true);

	const context = await runHook({
		command: 'node -e "console.log(JSON.stringify({hookSpecificOutput:{hookEventName:\'UserPromptSubmit\',additionalContext:\'记得X\'}}))"',
		payload: {}
	});
	assert.equal(context.additionalContext, "记得X");
});

await check("timeout kills the hook", async () => {
	const res = await runHook({
		command: "node -e \"setTimeout(()=>{},60000)\"",
		payload: {},
		timeoutMs: 800
	});
	assert.equal(res.timedOut, true);
	assert.equal(res.blocked, false);
});

/* ---------- format paths ---------- */

await check("extractPaths finds common key names", () => {
	assert.deepEqual(extractPaths({ file_path: "C:\\x\\a.ts" }, { path: "C:\\x\\b.ts" }), ["C:\\x\\a.ts", "C:\\x\\b.ts"]);
	assert.deepEqual(extractPaths({ foo: 1 }), []);
});

/* ---------- audit redaction ---------- */

await check("redact masks sensitive keys recursively", () => {
	const out = redact(
		{ Authorization: "Bearer x", nested: { apiKey: "k", ok: 1 }, list: [{ token: "t" }] },
		["authorization", "*key*", "*token*"]
	);
	assert.equal(out.Authorization, "[redacted]");
	assert.equal(out.nested.apiKey, "[redacted]");
	assert.equal(out.nested.ok, 1);
	assert.equal(out.list[0].token, "[redacted]");
});

/* ---------- formatOnSave path interpolation ---------- */

await check("interpolateFilePath quotes spaces and handles pre-quoted placeholders", () => {
	const p = "C:\\my dir\\file name.ts";
	assert.equal(interpolateFilePath("npx prettier --write {file}", p), `npx prettier --write "${p}"`);
	assert.equal(interpolateFilePath('node tool "{file}"', p), `node tool "${p}"`);
	assert.ok(!interpolateFilePath("x {file}", p).includes("\\\\"), "must not double backslashes");
});

/* ---------- webhook signing ---------- */

await check("signBody produces stable HMAC-SHA256 hex", () => {
	const body = '{"event":"Stop"}';
	const sig = signBody(body, "s3cret");
	assert.ok(sig.startsWith("sha256="));
	const expected = createHmac("sha256", "s3cret").update(body).digest("hex");
	assert.equal(sig, `sha256=${expected}`);
	assert.notEqual(signBody(body, "other"), sig);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
