/**
 * dsh-guard-hooks — Claude Code-style user-configurable hooks for DeepSeek Harness.
 *
 * Cordis plugin entry. Wires the hooks engine into DSH's tool waterfalls:
 *
 * - `tools/pre-execute` → rules table + PreToolUse script hooks
 *   (gate decisions: `{kind:'allow'} | {kind:'deny',reason} | {kind:'ask'}`)
 * - `tools/post-execute` → audit + formatOnSave + warn notes +
 *   PostToolUse script hooks, which may block with corrective feedback
 *
 * Lifecycle events (Stop / UserPromptSubmit / PreCompact / SessionStart /
 * approval-wait notifications) are wired in ./lifecycle.js.
 *
 * Robustness contract:
 * - A broken hooks.yaml never disables protection (last-good config snapshot).
 * - Every listener body is failure-isolated; hook crashes degrade to audit
 *   entries, never session errors.
 * - Invalid user patterns/matchers are reported once and match nothing.
 *
 * @module dsh-guard-hooks
 */

import crypto from "node:crypto";
import path from "node:path";
import { createConfigLoader } from "./config.js";
import { runEventHooks } from "./engine.js";
import { compileToolMatcher, onBrokenPattern } from "./patterns.js";
import { recordHookRun, recordInterception, recordToolCall } from "./audit.js";
import { pushWebhook } from "./webhook.js";
import { evaluateRules, denialReason as ruleDenialReason, askReason as ruleAskReason, warningNote, SHELL_TOOL_PATTERN } from "./features/rules.js";
import { formatFile, hasRuleForPath, extractPaths, EDIT_TOOL_PATTERN } from "./features/format.js";
import { notifyDesktop } from "./notify.js";
import { wireLifecycleEvents } from "./lifecycle.js";

/** Cordis plugin name. */
const name = "dsh-guard-hooks";

/** No services required: everything rides public waterfall events. */
const inject = [];

/** Warn-eviction caps for cross-listener state. */
const MAX_PENDING_MAP_SIZE = 512;

/**
 * @param {object} ctx - cordis context.
 * @param {object} _config - entry config from cordis.patch.yml (currently unused;
 *   all user configuration lives in ~/.dsh/hooks.yaml and .dsh/hooks.yaml).
 */
function apply(ctx, _config) {
	/** Mutable plugin state shared across listeners. */
	const state = {
		/** warn-rule hits waiting to be attached post-execute, keyed by callId. */
		pendingWarns: new Map(),
		/** pre-execute start timestamps, keyed by callId (duration auditing). */
		pendingStarts: new Map(),
		/** Stop-hook continuation budget per agent id (CC block-and-continue). */
		stopContinues: new Map(),
		/** last loaded config snapshot (for lifecycle events / crash fallback). */
		config: null,
		/** resolved workspace cwd cache. */
		cwd: undefined,
		sessionId: undefined,
		logger: console
	};

	const evictOldest = (map) => {
		while (map.size > MAX_PENDING_MAP_SIZE) {
			const oldest = map.keys().next().value;
			map.delete(oldest);
		}
	};

	const log = (...args) => {
		try {
			state.logger.info?.("[dsh-guard-hooks]", ...args);
		} catch {
			/* logging never breaks hooks */
		}
	};

	/** Identical warning lines are logged at most once a minute. */
	const warnedRecently = new Map();
	const logOnce = (message) => {
		if (!message) return;
		const now = Date.now();
		if (now - (warnedRecently.get(message) ?? 0) < 60_000) return;
		if (warnedRecently.size > 200) warnedRecently.clear();
		warnedRecently.set(message, now);
		log(message);
	};

	onBrokenPattern((message) => logOnce(`[dsh-guard-hooks] ${message}`));

	/** Cached loader: stat-based invalidation + last-good on broken YAML. */
	const configLoader = createConfigLoader(() => resolveCwd(), { onWarning: (message) => logOnce(`[dsh-guard-hooks] ${message}`) });

	function currentConfig() {
		try {
			const config = configLoader.get();
			state.config = config;
			return config;
		} catch (error) {
			logOnce("[dsh-guard-hooks] config load failed, keeping previous snapshot");
			logOnce(String(error?.stack ?? error));
			return state.config;
		}
	}

	/**
	 * Best-effort workspace root. Prefers the agent's own session header cwd so
	 * multi-workspace sessions each resolve their own root; falls back to the
	 * host process cwd.
	 *
	 * IMPORTANT: never reads undeclared ctx services — Cordis context proxies
	 * throw on property access without an `inject` declaration, and a throw
	 * here once deadlocked every tool call in the host.
	 */
	function resolveCwd(agentHint) {
		try {
			const headerCwd = agentHint?.session?.header?.cwd ?? agentHint?.session?.cwd;
			if (typeof headerCwd === "string" && headerCwd.trim()) return path.resolve(headerCwd);
		} catch {
			/* header access is best-effort */
		}
		if (state.cwd) return state.cwd;
		const candidates = [process.env.DSH_WORKSPACE, process.cwd()];
		for (const candidate of candidates) {
			if (typeof candidate === "string" && candidate.trim()) {
				state.cwd = path.resolve(candidate);
				break;
			}
		}
		return state.cwd ?? process.cwd();
	}

	/** Session id best-effort: per-agent when available, else stable per process. */
	function sessionId(agent) {
		if (agent?.id) return String(agent.id);
		if (!state.sessionId) state.sessionId = `proc-${process.pid}`;
		return state.sessionId;
	}

	/** Desktop toast when something was intercepted (opt-in). */
	const interceptNotify = (config, summary) => {
		if (config.notify.onIntercept) {
			notifyDesktop("DSH hooks 拦截", summary, { sound: config.notify.sound });
		}
	};

	/* ------------------------------------------------------------------ */
	/* PreToolUse                                                          */
	/* ------------------------------------------------------------------ */

	ctx.on("tools/pre-execute", async (exec, next) => {
		const callKey = String(exec.callId ?? "");
		// Start marker consumed by post-execute for duration auditing. Calls
		// that never reach post-execute (denied/aborted) are bounded by the
		// eviction cap instead of exact cleanup.
		state.pendingStarts.set(callKey, Date.now());
		evictOldest(state.pendingStarts);
		return runPreToolGate(exec, next);
	});

	/**
	 * The actual pre-tool decision logic, split out so timing cleanup wraps it.
	 */
	async function runPreToolGate(exec, next) {
		const callKey = String(exec.callId ?? "");
		const toolName = String(exec.name ?? "");
		const args = exec.arguments;
		const config = currentConfig();
		if (!config) return next();

		// ① Built-in command rules against shell-tool input.
		const shellInput = shellInputOf(toolName, args);
		if (shellInput !== null) {
			const verdict = evaluateRules(config.rules, shellInput);

			if (verdict.action === "deny") {
				log(`deny ${toolName}: ${shellInput.slice(0, 200)} (rule: ${verdict.pattern})`);
				recordInterception(config.audit, interceptionRecord("PreToolUse", "deny", toolName, shellInput, verdict.pattern, callKey, exec));
				interceptNotify(config, `${toolName} 命中 deny 规则`);
				pushWebhook(config.webhook, hookPayload("PreToolUse", { tool: toolName, input: shellInput, deniedBy: "rules" }, state), () => {});
				return { kind: "deny", reason: ruleDenialReason(verdict, toolName) };
			}

			if (verdict.action === "ask") {
				recordInterception(config.audit, interceptionRecord("PreToolUse", "ask", toolName, shellInput, verdict.pattern, callKey, exec));
				pushWebhook(config.webhook, hookPayload("PreToolUse", { tool: toolName, input: shellInput, askBy: "rules" }, state), () => {});
				// Route through DSH's approval seam: allowed-once proceeds,
				// every other outcome fails closed.
				return { kind: "ask", reason: ruleAskReason(verdict, toolName) };
			}

			if (verdict.action === "allow") {
				recordInterception(config.audit, interceptionRecord("PreToolUse", "allow", toolName, shellInput, verdict.pattern, callKey, exec));
				return next(); // short-circuit: skip PreToolUse script hooks entirely
			}

			if (verdict.action === "warn") {
				state.pendingWarns.set(callKey, warningNote(verdict, toolName));
				evictOldest(state.pendingWarns);
				recordInterception(config.audit, interceptionRecord("PreToolUse", "warn", toolName, shellInput, verdict.pattern, callKey, exec));
				// fall through: warn does not block
			}
		}

		// ② User-defined PreToolUse script hooks.
		const entries = matchedEntries(config.hooks.PreToolUse, toolName);
		if (entries.length === 0) return next();

		let vetoReason = null;
		let askText = null;
		const results = await runEventHooks(entries, {
			event: "PreToolUse",
			sessionId: sessionId(exec.agent),
			cwd: resolveCwd(exec.agent),
			toolName,
			payloadExtra: { tool: toolName, input: args ?? null }
		}).catch((error) => {
			logOnce(`[dsh-guard-hooks] PreToolUse hooks crashed (isolated): ${error?.message ?? error}`);
			return [];
		});

		for (const result of results) {
			recordHookRun(config.audit, hookRunRecord("PreToolUse", toolName, result));
			if (result.blocked && !vetoReason) {
				vetoReason = result.reason || `blocked by hook: ${result.command}`;
			}
			if (!vetoReason && result.ask && !askText) {
				askText = result.reason || `needs approval by hook: ${result.command}`;
			}
		}

		if (vetoReason) {
			log(`blocked by hook: ${vetoReason.slice(0, 160)}`);
			recordInterception(config.audit, interceptionRecord("PreToolUse", "deny", toolName, shellInputOf(toolName, args) ?? "", undefined, callKey, exec, vetoReason));
			interceptNotify(config, `${toolName} 被 PreToolUse 钩子拦截`);
			return { kind: "deny", reason: vetoReason };
		}

		// A PreToolUse hook can route the call through the human-approval gate
		// via the new permissionDecision:"ask" syntax — fail-closed like rules.ask.
		if (askText) {
			log(`ask by hook: ${askText.slice(0, 160)}`);
			recordInterception(config.audit, interceptionRecord("PreToolUse", "ask", toolName, shellInputOf(toolName, args) ?? "", undefined, callKey, exec, askText));
			interceptNotify(config, `${toolName} 被 PreToolUse 钩子转入人工审批`);
			pushWebhook(config.webhook, hookPayload("PreToolUse", { tool: toolName, input: shellInputOf(toolName, args) ?? null, askBy: "hooks" }, state), () => {});
			return { kind: "ask", reason: askText };
		}

		return next();
	}

	/* ------------------------------------------------------------------ */
	/* PostToolUse                                                         */
	/* ------------------------------------------------------------------ */

	ctx.on("tools/post-execute", async (exec, result, next) => {
		const downstream = await next();
		try {
			const config = currentConfig();
			if (!config) return downstream;

			const toolName = String(exec.name ?? "");
			const isError = downstream?.kind === "block" || Boolean(result?.isError);
			const callKey = String(exec.callId ?? "");

			const startedAt = state.pendingStarts.get(callKey);
			state.pendingStarts.delete(callKey);
			const durationMs = startedAt ? Date.now() - startedAt : undefined;

			recordToolCall(config.audit, {
				tool: toolName,
				input: safeSummary(exec.arguments),
				isError,
				durationMs,
				callId: callKey,
				agent: exec.agent?.id ? String(exec.agent.id) : undefined
			});

			const extraContexts = [];

			// ① Flush pending warn notes for this call.
			const warnNote = state.pendingWarns.get(callKey);
			if (warnNote) {
				state.pendingWarns.delete(callKey);
				extraContexts.push(userMessage(warnNote, `rules-warn ${toolName}`, exec.agent?.session));
			}

			// ② Format-on-save for successful edit-class calls.
			if (!isError && config.formatOnSave.enabled && toolMatches(toolName, EDIT_TOOL_PATTERN)) {
				const paths = extractPaths(exec.arguments, result ?? downstream);
				for (const filePath of paths.slice(0, 8)) {
					if (!hasRuleForPath(config.formatOnSave, filePath)) continue;
					const { contexts } = await formatFile(config.formatOnSave, filePath, resolveCwd(exec.agent));
					for (const context of contexts) extraContexts.push(userMessage(context, `formatOnSave ${path.basename(filePath)}`, exec.agent?.session));
				}
			}

			// ③ User-defined PostToolUse script hooks (awaited sync ones).
			let hookBlockFeedback = null;
			const entries = matchedEntries(config.hooks.PostToolUse, toolName);
			if (entries.length > 0) {
				const results = await runEventHooks(entries, {
					event: "PostToolUse",
					sessionId: sessionId(exec.agent),
					cwd: resolveCwd(exec.agent),
					toolName,
					payloadExtra: {
						tool: toolName,
						input: exec.arguments ?? null,
						output: summarizeOutput(result ?? downstream)
					}
				}).catch(() => []);

				for (const hookResult of results) {
					recordHookRun(config.audit, hookRunRecord("PostToolUse", toolName, hookResult));
					if (hookResult.blocked && !hookBlockFeedback) {
						hookBlockFeedback = hookResult.reason || "blocked by PostToolUse hook";
					}
					if (hookResult.additionalContext) {
						extraContexts.push(userMessage(hookResult.additionalContext, `PostToolUse ${toolName}`, exec.agent?.session));
					}
				}
			}

			pushWebhook(
				config.webhook,
				hookPayload("PostToolUse", { tool: toolName, isError }, state),
				() => {}
			);

			// ④ A blocking PostToolUse hook overrides an otherwise-accepted result
			//    with corrective feedback (Claude Code semantics).
			if (hookBlockFeedback) {
				return {
					kind: "block",
					feedback: [{ type: "text", text: `[hooks] ${hookBlockFeedback}` }],
					additionalContexts: [...extraContexts, ...(downstream?.additionalContexts ?? [])]
				};
			}

			if (extraContexts.length === 0) return downstream;

			// Splice our contexts in front, preserving whatever shape arrived
			// (same contract as @deepseek-ai/dsh-repeat-tool-reminder).
			if (downstream?.kind === "block") {
				return {
					kind: "block",
					feedback: downstream.feedback,
					additionalContexts: [...extraContexts, ...(downstream.additionalContexts ?? [])]
				};
			}
			return {
				...(downstream ?? {}),
				additionalContexts: [...extraContexts, ...(downstream?.additionalContexts ?? [])]
			};
		} catch (error) {
			logOnce(`[dsh-guard-hooks] post-execute stage failed (isolated): ${error?.message ?? error}`);
			return downstream;
		}
	});

	/* ------------------------------------------------------------------ */
	/* Lifecycle events                                                    */
	/* ------------------------------------------------------------------ */

	wireLifecycleEvents(ctx, {
		name,
		state,
		currentConfig,
		resolveCwd,
		userMessage,
		log,
		logOnce,
		interceptNotify
	});
}

/* -------------------------------------------------------------------- */
/* helpers                                                              */
/* -------------------------------------------------------------------- */

/** Extract the shell command text from shell-like tool arguments. */
function shellInputOf(toolName, args) {
	if (!toolMatches(toolName, SHELL_TOOL_PATTERN)) return null;
	if (args && typeof args === "object") {
		for (const key of ["command", "cmd", "script", "commandLine"]) {
			if (typeof args[key] === "string") return args[key];
		}
	}
	if (typeof args === "string") return args;
	return null;
}

/** Match a tool name against a regex-source pattern, safely. */
function toolMatches(toolName, patternSource) {
	const { matches } = compileToolMatcher(patternSource);
	return matches(toolName);
}

/** Hook entries whose matcher accepts this tool name. */
function matchedEntries(entries, toolName) {
	return (entries ?? []).filter((entry) => {
		if (!entry.matcher) return true;
		const { matches } = compileToolMatcher(entry.matcher);
		return matches(toolName);
	});
}

/** Compact JSON-safe output summary for payloads. */
function summarizeOutput(result) {
	try {
		if (result === undefined || result === null) return null;
		const content = Array.isArray(result.content) ? result.content : undefined;
		if (content) {
			return {
				isError: Boolean(result.isError),
				text: content
					.filter((block) => block?.type === "text")
					.map((block) => block.text)
					.join("\n")
					.slice(0, 4000)
			};
		}
		const json = JSON.stringify(result);
		return json.length > 4000 ? `${json.slice(0, 4000)}…` : result;
	} catch {
		return "[unserializable]";
	}
}

/** JSON-safe, size-capped snapshot of tool arguments for audit lines. */
function safeSummary(value) {
	try {
		if (value === undefined || value === null) return null;
		const json = JSON.stringify(value);
		if (json.length <= 4000) return value;
		return `${json.slice(0, 4000)}…[truncated ${json.length} chars]`;
	} catch {
		return "[unserializable]";
	}
}

/**
 * Producer-owned source kind for plugin-authored messages.
 *
 * Session v4 refuses the released `{kind:"plugin", plugin:…}` wrapper at
 * admission ("format v4 message requires a producer-owned source kind"), so a
 * plugin that keeps writing it breaks every new session's first step. Match the
 * legacy shape on v3 and the producer-owned kind on v4, as other plugins do.
 */
export function pluginMessageSource(session) {
	const version = Number(session?.header?.version);
	return version >= 4
		? { kind: "plugin:dsh-guard-hooks" }
		: { kind: "plugin", plugin: "dsh-guard-hooks" };
}

/** Build one plugin-sourced user message (load-bearing `source`, see repeat-tool-reminder). */
function userMessage(text, summary, session) {
	return Object.freeze(
		structuredClone({
			id: crypto.randomUUID(),
			role: "user",
			content: [{ type: "text", text: String(text).slice(0, 8000) }],
			source: { ...pluginMessageSource(session), form: "notice", summary: String(summary ?? "").slice(0, 160) }
		})
	);
}

/** Shared webhook/payload envelope. */
function hookPayload(event, extra, state) {
	return {
		event,
		sessionId: state.sessionId,
		cwd: state.cwd ?? process.cwd(),
		timestamp: new Date().toISOString(),
		...extra
	};
}

function interceptionRecord(event, action, tool, input, pattern, callId, exec, reason) {
	return {
		event,
		source: "rules",
		action,
		tool,
		input: safeSummary(input),
		rule: pattern,
		reason,
		callId,
		agent: exec?.agent?.id ? String(exec.agent.id) : undefined
	};
}

function hookRunRecord(hookEvent, tool, result) {
	return {
		hookEvent,
		tool,
		command: result.command,
		ok: result.ok,
		blocked: result.blocked,
		approved: result.approved,
		timedOut: result.timedOut,
		exitCode: result.exitCode,
		durationMs: result.durationMs,
		stderrTail: result.stderrTail || undefined
	};
}

export { apply, inject, name };
