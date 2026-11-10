/**
 * Hook process engine: run user hook commands as child processes with the
 * Claude Code-compatible protocol.
 *
 * Protocol:
 * - The event payload is written to the child's stdin as JSON.
 * - Environment: DSH_EVENT, DSH_TOOL_NAME, DSH_SESSION_ID, DSH_CWD plus the
 *   parent environment.
 * - Exit code 0 → pass. Exit code 2 → block; stderr is the reason fed back to
 *   the model. Any other code → non-blocking error (audited, never fatal).
 * - stdout JSON decisions override exit-code semantics. Two syntaxes:
 *   classic `{"decision":"block"|"approve","reason":...}` /
 *   `{"additionalContext":"..."}` and the newer Claude Code
 *   `{"hookSpecificOutput":{"hookEventName":...,"permissionDecision":
 *   "allow"|"deny"|"ask","permissionDecisionReason":...}}`; when both shapes
 *   appear the newer one wins.
 *
 * Hooks never crash the session: every failure resolves to a structured
 * result instead of throwing.
 *
 * @module dsh-guard-hooks/engine
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

/** Cap on concurrently running async hooks; extras queue FIFO. */
const MAX_CONCURRENT_ASYNC = 8;
let inFlightAsync = 0;
const asyncQueue = [];

function scheduleAsync(task) {
	if (inFlightAsync < MAX_CONCURRENT_ASYNC) {
		inFlightAsync += 1;
		task().finally(() => {
			inFlightAsync -= 1;
			const nextTask = asyncQueue.shift();
			if (nextTask) scheduleAsync(nextTask);
		});
	} else if (asyncQueue.length < 64) {
		asyncQueue.push(task);
	} else {
		// Queue overflow: drop oldest to keep memory bounded under storms.
		asyncQueue.shift();
		asyncQueue.push(task);
	}
}

/** JSON.stringify that survives circular/self-referential payloads. */
export function safeJsonStringify(value) {
	const seen = new WeakSet();
	return JSON.stringify(value, (_key, item) => {
		if (typeof item !== "object" || item === null) return typeof item === "bigint" ? String(item) : item;
		if (seen.has(item)) return "[circular]";
		seen.add(item);
		return item;
	});
}

/** Result of one hook execution. */
// {
//   ok, blocked, approved, ask, timedOut,
//   exitCode, stdout, stderr,
//   decision?, reason?, additionalContext?, durationMs
// }

/**
 * Run one hook command synchronously (awaited).
 *
 * @param {object} options
 * @param {string} options.command - shell command line to run.
 * @param {object} options.payload - JSON event payload piped to stdin.
 * @param {number} [options.timeoutMs] - kill the child after this long.
 * @param {string} [options.cwd] - working directory for the child.
 * @param {Record<string,string>} [options.env] - extra env vars.
 * @param {boolean|string} [options.shell] - `true`/undefined = platform shell;
 *   a string = that shell executable; `false` = spawn argv directly.
 * @returns {Promise<object>} structured result, never rejects.
 */
export function runHook({ command, payload, timeoutMs = 10_000, cwd, env, shell }) {
	return new Promise((resolve) => {
		const startedAt = Date.now();
		let settled = false;
		const finish = (partial) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(interpret(partial, Date.now() - startedAt));
		};

		let stdinText = "";
		try {
			stdinText = safeJsonStringify(payload);
		} catch {
			stdinText = "";
		}

		const child = spawn(command, {
			shell: shell === undefined ? true : shell,
			windowsHide: true,
			cwd: cwd && fs.existsSync(cwd) ? cwd : undefined,
			env: { ...process.env, ...env }
		});

		// A child that exits before draining its stdin makes the async payload
		// write fail with EPIPE; unhandled, that error would crash the host
		// process. Launch failures still surface via `child.on("error")`.
		child.stdin?.on("error", () => {});

		const chunks = { out: [], err: [] };
		child.stdout?.on("data", (chunk) => chunks.out.push(chunk));
		child.stderr?.on("data", (chunk) => chunks.err.push(chunk));

		const timer = setTimeout(() => {
			if (settled || child.exitCode !== null || child.signalCode) return;
			killTree(child);
			finish({ stdoutText: buffered(chunks.out), stderrText: `${buffered(chunks.err)}\nhooks: timed out after ${timeoutMs}ms`.trim(), signal: "SIGTERM", timedOut: true });
		}, clampTimeoutMs(timeoutMs));

		child.on("error", (error) => {
			finish({ stdoutText: buffered(chunks.out), stderrText: `${buffered(chunks.err)}\nhooks: failed to launch: ${error.message}`.trim(), timedOut: false });
		});
		child.on("close", (exitCode, signal) => {
			finish({ stdoutText: buffered(chunks.out), stderrText: buffered(chunks.err), exitCode, signal, timedOut: false });
		});

		try {
			child.stdin?.end(stdinText);
		} catch {
			child.stdin?.end();
		}
	});
}

/** Clamp a user timeout into [100ms, 10min]; falls back to 10s when invalid. */
function clampTimeoutMs(value) {
	const n = Number(value);
	if (!Number.isFinite(n) || n <= 0) return 10_000;
	return Math.min(Math.max(Math.floor(n), 100), 600_000);
}

/**
 * Fire-and-forget variant for async hooks; result goes to `onDone`.
 * Concurrency-capped so a burst of events cannot spawn unbounded children.
 *
 * @param {object} options - same as {@link runHook} plus optional onDone.
 */
export function runHookAsync({ onDone, ...options }) {
	scheduleAsync(() =>
		runHook(options).then(
			(result) => onDone?.(result),
			() => onDone?.(null)
		)
	);
}

function buffered(chunks) {
	return Buffer.concat(chunks).toString("utf8").slice(0, 64_000);
}

/** Best-effort process-tree kill (Windows needs taskkill for children). */
export function killTree(child) {
	try {
		if (process.platform === "win32") {
			spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true });
		} else {
			child.kill("SIGKILL");
		}
	} catch {
		try {
			child.kill("SIGKILL");
		} catch {
			/* already gone */
		}
	}
}

/**
 * Turn raw child output into the semantic result.
 *
 * @private
 */
function interpret(raw, durationMs) {
	const { stdoutText = "", stderrText = "", exitCode = null, signal = null, timedOut = false } = raw;
	const result = {
		ok: false,
		blocked: false,
		approved: false,
		ask: false,
		timedOut,
		exitCode,
		signal,
		stdout: stdoutText,
		stderr: stderrText,
		stderrTail: stderrText.trim().slice(-400),
		durationMs
	};

	// Structured stdout decisions win over exit codes. The newer Claude Code
	// hookSpecificOutput shape takes precedence over the classic decision field.
	const parsed = parseJsonObject(stdoutText);
	if (parsed && typeof parsed === "object") {
		const hso = typeof parsed.hookSpecificOutput === "object" && parsed.hookSpecificOutput !== null ? parsed.hookSpecificOutput : null;
		if (hso) {
			const reason = typeof hso.permissionDecisionReason === "string"
				? hso.permissionDecisionReason
				: typeof parsed.reason === "string"
					? parsed.reason
					: undefined;
			const pd = typeof hso.permissionDecision === "string" ? hso.permissionDecision.toLowerCase() : null;
			if (pd === "deny" || pd === "block") {
				result.blocked = true;
				result.reason = reason ?? stderrText.trim() ?? "blocked by hook";
				return result;
			}
			if (pd === "ask") {
				result.ask = true;
				result.reason = reason ?? "asked by hook";
				return result;
			}
			if (pd === "allow" || pd === "approve") {
				result.approved = true;
				result.ok = true;
				if (reason) result.reason = reason;
				return result;
			}
			if (typeof hso.additionalContext === "string" && hso.additionalContext.trim()) {
				result.additionalContext = hso.additionalContext;
				result.ok = true;
				return result;
			}
		}
		if (typeof parsed.decision === "string") {
			const decision = parsed.decision.toLowerCase();
			if (decision === "block" || decision === "deny") {
				result.blocked = true;
				result.reason = typeof parsed.reason === "string" ? parsed.reason : stderrText || "blocked by hook";
				return result;
			}
			if (decision === "approve" || decision === "allow") {
				result.approved = true;
				result.ok = true;
				if (typeof parsed.reason === "string") result.reason = parsed.reason;
				return result;
			}
		}
		if (typeof parsed.additionalContext === "string" && parsed.additionalContext.trim()) {
			result.additionalContext = parsed.additionalContext;
			result.ok = true;
			return result;
		}
	}

	if (timedOut) return result;
	if (exitCode === 0) {
		result.ok = true;
		return result;
	}
	if (exitCode === 2) {
		result.blocked = true;
		result.reason = stderrText.trim() || stdoutText.trim() || "blocked by hook (exit 2)";
		return result;
	}
	// Non-zero, non-2: non-blocking error.
	result.error = true;
	return result;
}

/** Parse the first JSON object found in a stdout blob; tolerate log noise around it. */
function parseJsonObject(text) {
	const trimmed = text.trim();
	if (!trimmed) return null;
	try {
		const direct = JSON.parse(trimmed);
		return direct && typeof direct === "object" && !Array.isArray(direct) ? direct : null;
	} catch {
		/* fall through: scan for an embedded object */
	}
	const start = trimmed.indexOf("{");
	const end = trimmed.lastIndexOf("}");
	if (start >= 0 && end > start) {
		try {
			const candidate = JSON.parse(trimmed.slice(start, end + 1));
			return candidate && typeof candidate === "object" ? candidate : null;
		} catch {
			return null;
		}
	}
	return null;
}

/** Build the stdin payload shared by all events. */
export function eventPayload({ event, sessionId, cwd, extra }) {
	return {
		event,
		sessionId: sessionId ?? null,
		cwd: cwd ?? process.cwd(),
		timestamp: new Date().toISOString(),
		...extra
	};
}

/** Env vars exposed to every hook child process. */
export function hookEnv({ event, toolName, sessionId, cwd }) {
	const env = {};
	if (event !== undefined) env.DSH_EVENT = event;
	if (toolName !== undefined) env.DSH_TOOL_NAME = toolName;
	if (sessionId !== undefined) env.DSH_SESSION_ID = sessionId;
	if (cwd !== undefined) env.DSH_CWD = cwd;
	return env;
}

/**
 * Sequentially run every matching hook entry for one event.
 *
 * Stops early only when a hook blocks (the block wins immediately).
 *
 * @param {Array<{command:string, matcher?:string, timeoutMs:number, async:boolean}>} entries
 * @param {object} context - {event, sessionId, cwd, toolName, payloadExtra, matchesTool}
 * @returns {Promise<object[]>} results of synchronously-run hooks.
 */
export async function runEventHooks(entries, context) {
	const results = [];
	for (const entry of entries) {
		const spawnOptions = {
			command: entry.command,
			payload: eventPayload({ ...context, extra: context.payloadExtra }),
			timeoutMs: entry.timeoutMs,
			cwd: context.cwd,
			env: hookEnv(context),
			shell: entry.shell
		};
		if (entry.async) {
			runHookAsync(spawnOptions);
			continue;
		}
		const result = await runHook(spawnOptions);
		result.command = entry.command;
		results.push(result);
		if (result.blocked) break;
	}
	return results;
}
