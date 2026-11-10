/**
 * Integration tests: drive lib/index.js through a mock cordis context,
 * emulating the waterfall dispatch semantics of the real event bus.
 *
 * Run: node test/integration.mjs
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { apply } from "../lib/index.js";

/** Minimal cordis stand-in with real waterfall composition order. */
class MockCtx {
	constructor() {
		this.listeners = new Map();
		this.logger = console;
	}
	on(name, fn) {
		if (!this.listeners.has(name)) this.listeners.set(name, []);
		this.listeners.get(name).push(fn);
		return () => {};
	}
	/**
	 * Emulate ctx.waterfall(name, ...args, innerNext):
	 * listeners wrap the chain outermost-first; `next()` re-dispatches with the
	 * same (mutable) arguments; falling off the end invokes innerNext.
	 */
	async waterfall(name, ...args) {
		const cbs = [...(this.listeners.get(name) ?? [])];
		const inner = args.pop();
		const step = (index, callArgs) => {
			const listener = cbs[index];
			const next = () => step(index + 1, callArgs);
			if (!listener) return inner(...callArgs);
			return listener(...callArgs, next);
		};
		return step(0, args);
	}
}

let passed = 0;
let failed = 0;
const failures = [];
async function check(label, fn) {
	try {
		await fn();
		passed += 1;
		console.log(`ok   ${label}`);
	} catch (error) {
		failed += 1;
		failures.push(`${label}: ${error.message}`);
		console.log(`FAIL ${label}: ${error.message}`);
	}
}

/* ---------- environment ---------- */

const home = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-int-home-"));
const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-int-repo-"));
fs.mkdirSync(path.join(home, "audit"), { recursive: true });

const auditPath = path.join(home, "audit", "test.jsonl");
const userYaml = [
	"rules:",
	"  deny:",
	'    - "rm -rf /*"',
	"  warn:",
	'    - "git reset --hard*"',
	"notify:",
	"  onStop: true",
	"audit:",
	"  enabled: true",
	`  path: ${JSON.stringify(auditPath)}`,
	"hooks:",
	"  PreToolUse:",
	'    - matcher: "Bash"',
	"      command: \"exit 2\"",
	"  PostToolUse:",
	'    - command: "node -e \\"console.log(JSON.stringify({additionalContext:\'tool-done\'}))\\""',
	"  UserPromptSubmit:",
	"    - command: \"node -e \\\"console.log(JSON.stringify({additionalContext:'remember-X'}))\\\"\"",
	"formatOnSave:",
	"  rules:",
	'    - match: "*.txt"',
	"      command: \"node -e \\\"require('fs').writeFileSync(process.env.DSH_FORMAT_FILE + '.formatted','')\\\"\""
].join("\n");
fs.writeFileSync(path.join(home, "hooks.yaml"), userYaml);

process.env.DSH_HOME = home;
process.chdir(repo);

const ctx = new MockCtx();
apply(ctx, {});

const exec = (over = {}) => ({
	callId: over.callId ?? "c1",
	name: over.name ?? "Pwsh",
	arguments: over.arguments ?? {},
	signal: new AbortController().signal
});

await check("rules.deny blocks before any hook runs", async () => {
	const decision = await ctx.waterfall("tools/pre-execute", exec({ arguments: { command: "rm -rf /" } }), () =>
		Promise.resolve({ kind: "allow" })
	);
	assert.equal(decision.kind, "deny");
	assert.ok(decision.reason.includes("rm -rf"));
});

await check("PreToolUse script hook blocks via exit 2", async () => {
	const decision = await ctx.waterfall("tools/pre-execute", exec({ name: "Bash", arguments: { command: "echo hi" } }), () =>
		Promise.resolve({ kind: "allow" })
	);
	assert.equal(decision.kind, "deny");
});

await check("warn rule passes but attaches note post-execute", async () => {
	await ctx.waterfall("tools/pre-execute", exec({ callId: "cW", arguments: { command: "git reset --hard HEAD~1" } }), () =>
		Promise.resolve({ kind: "allow" })
	);
	const out = await ctx.waterfall(
		"tools/post-execute",
		exec({ callId: "cW", arguments: { command: "git reset --hard HEAD~1" } }),
		{ content: [{ type: "text", text: "done" }] },
		(result) => Promise.resolve({ kind: "accept", content: result.content })
	);
	assert.equal(out.kind, "accept");
	const contexts = out.additionalContexts ?? [];
	const warnContext = contexts.find((m) => JSON.stringify(m).includes("谨慎规则"));
	assert.ok(warnContext, "warn note missing from additionalContexts");
	assert.equal(warnContext.source.plugin, "dsh-guard-hooks");
});

await check("formatOnSave runs on matching edit-tool writes", async () => {
	const target = path.join(repo, "saved.txt");
	fs.writeFileSync(target, "content");
	await ctx.waterfall("tools/pre-execute", exec({ callId: "cF", name: "StrReplaceEditor", arguments: { file_path: target } }), () =>
		Promise.resolve({ kind: "allow" })
	);
	await ctx.waterfall(
		"tools/post-execute",
		exec({ callId: "cF", name: "StrReplaceEditor", arguments: { file_path: target } }),
		{ content: [{ type: "text", text: "written" }] },
		() => Promise.resolve({ kind: "accept", content: [{ type: "text", text: "written" }] })
	);
	assert.ok(fs.existsSync(`${target}.formatted`), "formatter side effect missing");
});

await check("PostToolUse stdout additionalContext reaches the model", async () => {
	const out = await ctx.waterfall(
		"tools/post-execute",
		exec({ callId: "cP", name: "WebSearch", arguments: { query: "x" } }),
		{ content: [{ type: "text", text: "r" }] },
		(result) => Promise.resolve({ kind: "accept", content: result.content })
	);
	const texts = (out.additionalContexts ?? []).map((m) => m.content.map((b) => b.text).join(""));
	assert.ok(texts.some((t) => t.includes("tool-done")));
});

await check("PostToolUse context uses the producer-owned source on v4 sessions", async () => {
	const call = exec({ callId: "cP4", name: "WebSearch", arguments: { query: "x" } });
	call.agent = { session: { header: { version: 4 } } };
	const out = await ctx.waterfall(
		"tools/post-execute",
		call,
		{ content: [{ type: "text", text: "r" }] },
		(result) => Promise.resolve({ kind: "accept", content: result.content })
	);
	const hit = (out.additionalContexts ?? []).find((m) => JSON.stringify(m).includes("tool-done"));
	assert.ok(hit, "PostToolUse context missing");
	assert.equal(hit.source.kind, "plugin:dsh-guard-hooks");
});

await check("UserPromptSubmit hook can inject context", async () => {
	const batch = [{ id: "m1", role: "user", content: [{ type: "text", text: "hello" }] }];
	const decision = await ctx.waterfall("agent/pre-step", { messages: batch }, () =>
		Promise.resolve({ kind: "enter", messages: batch })
	);
	assert.equal(decision.kind, "enter");
	const injected = decision.messages.filter((m) => JSON.stringify(m).includes("remember-X"));
	assert.equal(injected.length, 1);
	assert.equal(injected[0].source.kind, "plugin");
});

await check("UserPromptSubmit injection uses the producer-owned source on v4 sessions", async () => {
	const batch = [{ id: "m4", role: "user", content: [{ type: "text", text: "hello" }] }];
	const decision = await ctx.waterfall(
		"agent/pre-step",
		{ messages: batch, agent: { session: { header: { version: 4 } } } },
		() => Promise.resolve({ kind: "enter", messages: batch })
	);
	const injected = decision.messages.filter((m) => JSON.stringify(m).includes("remember-X"));
	assert.equal(injected.length, 1);
	assert.equal(injected[0].source.kind, "plugin:dsh-guard-hooks");
	assert.equal(injected[0].source.form, "notice");
	assert.equal(injected[0].source.plugin, undefined);
});

await check("UserPromptSubmit injection keeps the v3 wrapper on v3 sessions", async () => {
	const batch = [{ id: "m5", role: "user", content: [{ type: "text", text: "hello" }] }];
	const decision = await ctx.waterfall(
		"agent/pre-step",
		{ messages: batch, agent: { session: { header: { version: 3 } } } },
		() => Promise.resolve({ kind: "enter", messages: batch })
	);
	const injected = decision.messages.filter((m) => JSON.stringify(m).includes("remember-X"));
	assert.equal(injected.length, 1);
	assert.equal(injected[0].source.kind, "plugin");
	assert.equal(injected[0].source.plugin, "dsh-guard-hooks");
});

await check("UserPromptSubmit hook can reject the prompt", async () => {
	const { apply: applyFresh } = await import(`../lib/index.js?t=${Date.now()}`);
	const home2 = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-int-home2-"));
	fs.mkdirSync(path.join(home2, "audit"), { recursive: true });
	fs.writeFileSync(
		path.join(home2, "hooks.yaml"),
		["hooks:", "  UserPromptSubmit:", "    - command: \"exit 2\"", "audit:", "  enabled: false"].join("\n")
	);
	const savedHome = process.env.DSH_HOME;
	process.env.DSH_HOME = home2;
	try {
		const ctx3 = new MockCtx();
		applyFresh(ctx3, {});
		const batch = [{ id: "m2", role: "user", content: [{ type: "text", text: "blocked please" }] }];
		const decision = await ctx3.waterfall("agent/pre-step", { messages: batch }, () =>
			Promise.resolve({ kind: "enter", messages: batch })
		);
		assert.deepEqual(decision, { kind: "reject" });
	} finally {
		process.env.DSH_HOME = savedHome;
		fs.rmSync(home2, { recursive: true, force: true });
	}
});

await check("host cancel-cause rejections stay terse (no scary failure log)", async () => {
	const lines = [];
	const originalInfo = console.info;
	console.info = (...args) => lines.push(args.map(String).join(" "));
	try {
		await assert.rejects(
			ctx.waterfall("agent/pre-step", { messages: [] }, () => Promise.reject({ kind: "user" })),
			(error) => Boolean(error) && error.kind === "user"
		);
	} finally {
		console.info = originalInfo;
	}
	const joined = lines.join("\n");
	assert.ok(!joined.includes("downstream failed"), "control-flow objects must not be logged as failures");
	assert.ok(joined.includes("interrupted by host"), "expected a terse interruption log line");
});

await check("turn/end triggers Stop notification without throwing", async () => {
	const handlers = ctx.listeners.get("session/event") ?? [];
	assert.ok(handlers.length >= 1);
	for (const handler of handlers) {
		handler(
			{ header: { id: "sess-123", cwd: repo } },
			{ type: "turn/end", data: { reason: "completed" } }
		);
		handler({ header: { id: "sess-123" } }, { type: "compaction/start", data: {} });
	}
	// give fire-and-forget hooks a beat
	await new Promise((resolve) => setTimeout(resolve, 300));
});

await check("audit log captured the story", () => {
	const lines = fs.readFileSync(auditPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
	const kinds = lines.map((entry) => entry.kind);
	assert.ok(kinds.includes("interception"), "no interception record");
	assert.ok(kinds.includes("tool-call"), "no tool-call record");
	assert.ok(kinds.includes("hook-run"), "no hook-run record");
	assert.ok(kinds.includes("prompt"), "no prompt record");
	assert.ok(kinds.includes("turn-stop"), "no turn-stop record");
	const denyLine = lines.find((entry) => entry.kind === "interception" && entry.action === "deny");
	assert.equal(denyLine.rule, "rm -rf /*");
});

/* ---------- round 2: robustness & new gates ---------- */

async function freshPlugin(hooksYaml) {
	const h = fs.mkdtempSync(path.join(os.tmpdir(), "dshh-r2-home-"));
	fs.mkdirSync(path.join(h, "audit"), { recursive: true });
	fs.writeFileSync(path.join(h, "hooks.yaml"), hooksYaml);
	const saved = process.env.DSH_HOME;
	process.env.DSH_HOME = h;
	const { apply: applyNew } = await import(`../lib/index.js?t=${Date.now()}-${Math.random()}`);
	const c = new MockCtx();
	applyNew(c, {});
	return {
		ctx: c,
		home: h,
		yamlPath: path.join(h, "hooks.yaml"),
		cleanup() {
			process.env.DSH_HOME = saved;
			try {
				fs.rmSync(h, { recursive: true, force: true, maxRetries: 3, retryDelay: 150 });
			} catch {
				/* best effort */
			}
		}
	};
}

await check("rules.ask routes through the human approval gate", async () => {
	const env = await freshPlugin(["rules:", "  ask:", '    - "deploy *"'].join("\n"));
	try {
		const decision = await env.ctx.waterfall(
			"tools/pre-execute",
			exec({ name: "Pwsh", arguments: { command: "deploy production" } }),
			() => Promise.resolve({ kind: "allow" })
		);
		assert.equal(decision.kind, "ask");
		assert.match(decision.reason ?? "", /人工确认|deploy/);
	} finally {
		env.cleanup();
	}
});

await check("blocking PostToolUse hook turns result into feedback", async () => {
	const env = await freshPlugin([
		"hooks:",
		"  PostToolUse:",
		"    - matcher: \"WebSearch\"",
		"      command: \"node -e \\\"console.log(JSON.stringify({decision:'block',reason:'结果已脱敏'}))\\\"\""
	].join("\n"));
	try {
		const out = await env.ctx.waterfall(
			"tools/post-execute",
			exec({ callId: "pb1", name: "WebSearch", arguments: { query: "x" } }),
			{ content: [{ type: "text", text: "secret stuff" }] },
			(result) => Promise.resolve({ kind: "accept", content: result.content })
		);
		assert.equal(out.kind, "block");
		assert.ok(JSON.stringify(out.feedback).includes("结果已脱敏"));
	} finally {
		env.cleanup();
	}
});

await check("broken YAML keeps last-good protection alive", async () => {
	const env = await freshPlugin(["rules:", "  deny:", '    - "blockme*"'].join("\n"));
	try {
		const args = { command: "blockme please" };
		const denied1 = await env.ctx.waterfall("tools/pre-execute", exec({ arguments: args }), () => Promise.resolve({ kind: "allow" }));
		assert.equal(denied1.kind, "deny");

		// Corrupt the file (different size guarantees statKey change).
		fs.writeFileSync(env.yamlPath, "rules: [unclosed\n");
		const denied2 = await env.ctx.waterfall("tools/pre-execute", exec({ arguments: args }), () => Promise.resolve({ kind: "allow" }));
		assert.equal(denied2.kind, "deny", "deny rule must survive a broken YAML");

		// Recover with a valid file that has no deny rule → passes again.
		await new Promise((resolve) => setTimeout(resolve, 30));
		fs.writeFileSync(env.yamlPath, "rules:\n  allow: [\"blockme*\"]\n");
		const allowed = await env.ctx.waterfall("tools/pre-execute", exec({ arguments: args }), () => Promise.resolve({ kind: "allow" }));
		assert.equal(allowed.kind, "allow", "config must recover after YAML fixed");
	} finally {
		env.cleanup();
	}
});

await check("audit log rotates at maxBytes", async () => {
	const auditPathRot = path.join(os.tmpdir(), `dshh-rot-${Date.now()}.jsonl`);
	const env = await freshPlugin([
		"audit:",
		"  enabled: true",
		`  path: ${JSON.stringify(auditPathRot)}`,
		"  maxBytes: 400"
	].join("\n"));
	try {
		for (let i = 0; i < 6; i += 1) {
			await env.ctx.waterfall(
				"tools/post-execute",
				exec({ callId: `r${i}`, name: "Pwsh", arguments: { command: `echo padding-${i}-${"x".repeat(60)}` } }),
				{ content: [{ type: "text", text: "ok" }] },
				() => Promise.resolve({ kind: "accept", content: [{ type: "text", text: "ok" }] })
			);
		}
		assert.ok(fs.existsSync(`${auditPathRot}.1`), "rotation backup missing");
		assert.ok(fs.existsSync(auditPathRot), "active audit file missing");
	} finally {
		try {
			fs.rmSync(`${auditPathRot}`, { force: true });
			fs.rmSync(`${auditPathRot}.1`, { force: true });
		} catch {
			/* best effort */
		}
		env.cleanup();
	}
});

await check("SubagentStop fires for child sessions only, SessionEnd on agent disposal", async () => {
	const subMark = path.join(os.tmpdir(), `dshh-sub-${Date.now()}.flag`);
	const endMark = path.join(os.tmpdir(), `dshh-end-${Date.now()}.flag`);
	const env = await freshPlugin([
		"hooks:",
		"  SubagentStop:",
		`    - command: "node -e \\"require('fs').writeFileSync(process.argv[1],'')\\" \\"${subMark.replace(/\\/g, "/")}\\""`,
		"  SessionEnd:",
		`    - command: "node -e \\"require('fs').writeFileSync(process.argv[1],'')\\" \\"${endMark.replace(/\\/g, "/")}\\""`,
		"audit:",
		"  enabled: false"
	].join("\n"));
	try {
		// Main-session turn/end must NOT trigger SubagentStop.
		for (const handler of env.ctx.listeners.get("session/event") ?? []) {
			handler({ header: { id: "main-1", cwd: repo } }, { type: "turn/end", data: { reason: "completed" } });
			handler({ header: { id: "child-1", parentSession: "main-1", cwd: repo } }, { type: "turn/end", data: { reason: { kind: "completed" } } });
		}
		await new Promise((resolve) => setTimeout(resolve, 400));
		assert.ok(fs.existsSync(subMark), "SubagentStop hook did not run for child session");

		// agent/disposed emit triggers SessionEnd.
		for (const handler of env.ctx.listeners.get("agent/disposed") ?? []) {
			handler({ agent: { id: "a-end" } });
		}
		await new Promise((resolve) => setTimeout(resolve, 400));
		assert.ok(fs.existsSync(endMark), "SessionEnd hook did not run on disposal");
	} finally {
		try {
			fs.rmSync(subMark, { force: true });
			fs.rmSync(endMark, { force: true });
		} catch {
			/* best effort */
		}
		env.cleanup();
	}
});

await check("Notification hooks fire on approval requests", async () => {
	const noteMark = path.join(os.tmpdir(), `dshh-note-${Date.now()}.flag`);
	const env = await freshPlugin([
		"hooks:",
		"  Notification:",
		`    - command: "node -e \\"require('fs').writeFileSync(process.argv[1],'')\\" \\"${noteMark.replace(/\\/g, "/")}\\""`,
		"audit:",
		"  enabled: false"
	].join("\n"));
	try {
		for (const handler of env.ctx.listeners.get("approval/request") ?? []) {
			await handler({ toolName: "Pwsh", reason: "危险命令" }, () => Promise.resolve({ kind: "allow-once" }));
		}
		await new Promise((resolve) => setTimeout(resolve, 400));
		assert.ok(fs.existsSync(noteMark), "Notification hook did not run on approval request");
	} finally {
		try {
			fs.rmSync(noteMark, { force: true });
		} catch {
			/* best effort */
		}
		env.cleanup();
	}
});

await check("blocking Stop hook steers continuation, capped by stop.maxContinues", async () => {
	const env = await freshPlugin([
		"hooks:",
		"  Stop:",
		"    - command: \"exit 2\"",
		"audit:",
		"  enabled: false"
	].join("\n"));
	try {
		const steered = [];
		const agent = {
			id: "ag-stop",
			session: { header: { cwd: repo } },
			steer(message) { steered.push(message); }
		};
		const fire = async () => {
			for (const handler of env.ctx.listeners.get("agent/turn-stopping") ?? []) {
				await handler({ agent, turn: 1 }, async () => {});
			}
		};
		await fire();
		await fire();
		await fire();
		await fire();
		assert.equal(steered.length, 3, "must steer exactly maxContinues (default 3) times");
		const text = steered[0]?.content?.[0]?.text ?? "";
		assert.ok(text.includes("blocked by hook"), "steer message must carry the block reason");
		assert.equal(steered[0]?.source?.plugin, "dsh-guard-hooks");
	} finally {
		env.cleanup();
	}
});

await check("fresh human prompt re-arms the Stop-continue budget", async () => {
	const env = await freshPlugin([
		"hooks:",
		"  Stop:",
		"    - command: \"exit 2\"",
		"audit:",
		"  enabled: false"
	].join("\n"));
	try {
		const steered = [];
		const agent = {
			id: "ag-reset",
			session: { header: { cwd: repo } },
			steer(message) { steered.push(message); }
		};
		const fireStop = async () => {
			for (const handler of env.ctx.listeners.get("agent/turn-stopping") ?? []) {
				await handler({ agent, turn: 1 }, async () => {});
			}
		};
		await fireStop();
		await fireStop();
		await fireStop();
		assert.equal(steered.length, 3);

		// A fresh human message arrives through pre-step → budget resets.
		const batch = [{ id: `human-${Date.now()}`, role: "user", content: [{ type: "text", text: "继续干活" }] }];
		for (const handler of env.ctx.listeners.get("agent/pre-step") ?? []) {
			await handler({ agent, messages: batch, turn: 2, step: 0, signal: new AbortController().signal }, () =>
				Promise.resolve({ kind: "enter", messages: batch })
			);
		}
		await fireStop();
		assert.equal(steered.length, 4, "budget must be re-armed by human input");
	} finally {
		env.cleanup();
	}
});

try {
	fs.rmSync(home, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
	fs.rmSync(repo, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
} catch {
	/* temp cleanup is best-effort on Windows */
}

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
