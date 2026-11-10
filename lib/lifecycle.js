/**
 * Lifecycle event wiring: UserPromptSubmit / Stop / PreCompact /
 * SessionStart / approval-wait notifications.
 *
 * Mapping (from DSH 0.1.1-rc.2 runtime):
 * - UserPromptSubmit → `agent/pre-step` waterfall (can reject / add context),
 *   observing fresh non-plugin user messages in each step batch.
 * - Stop            → persistent `session/event` with `type === 'turn/end'`.
 * - PreCompact      → `session/event` with `type === 'compaction/start'`.
 * - SessionStart    → `agent/session-start` emit.
 * - Approval wait   → `approval/request` waterfall (observe + always delegate).
 *
 * @module dsh-guard-hooks/lifecycle
 */

import { runEventHooks } from "./engine.js";
import { auditRecord, recordHookRun, recordInterception } from "./audit.js";
import { pushWebhook } from "./webhook.js";
import { notifyDesktop } from "./notify.js";

/**
 * Register all lifecycle listeners. Every registration and every dispatch is
 * failure-isolated: hooks must never break the agent loop.
 *
 * @param {object} ctx - cordis context.
 * @param {object} h - helpers from the entry module:
 *   `{ state, currentConfig, resolveCwd, userMessage, log }`.
 */
export function wireLifecycleEvents(ctx, h) {
	const { state, currentConfig, resolveCwd, userMessage, log, logOnce, interceptNotify } = h;

	/** Messages whose UserPromptSubmit hooks already ran (FIFO eviction). */
	const seenPrompts = new Map();

	function safe(fn, label) {
		return (...args) => {
			try {
				return fn(...args);
			} catch (error) {
				log(`${label} failed (isolated):`, error?.message ?? error);
			}
		};
	}

	async function runHooksSafe(entries, context) {
		try {
			const results = await runEventHooks(entries ?? [], context);
			for (const result of results) {
				recordHookRun(currentConfig().audit, {
					hookEvent: context.event,
					command: result.command,
					ok: result.ok,
					blocked: result.blocked,
					timedOut: result.timedOut,
					exitCode: result.exitCode,
					durationMs: result.durationMs
				});
			}
			return results;
		} catch (error) {
			log(`${context.event} hooks crashed (isolated):`, error?.message ?? error);
			return [];
		}
	}

	/* ------------------------------------------------------------------ */
	/* Notification when a tool call waits for human approval              */
	/* ------------------------------------------------------------------ */

	safe(() => {
		ctx.on("approval/request", async (req, next) => {
			try {
				const config = currentConfig();
				if (config.notify.onApprovalWait) {
					notifyDesktop(
						"DSH 等待你的审批",
						`工具 ${req?.toolName ?? "?"}${req?.reason ? `：${String(req.reason).slice(0, 80)}` : ""}`,
						{ sound: config.notify.sound }
					);
				}
				auditRecord(config.audit, {
					kind: "approval-request",
					time: new Date().toISOString(),
					toolName: req?.toolName,
					reason: req?.reason
				});
				// CC Notification alias #1: permission requests surface as
				// Notification hooks so user scripts get the same trigger point.
				if (config.hooks.Notification.length > 0 || config.webhook.url) {
					const notificationPayload = {
						event: "Notification",
						sessionId: req?.sessionId ? String(req.sessionId) : null,
						cwd: resolveCwd(),
						timestamp: new Date().toISOString(),
						message: `Claude needs your approval for ${req?.toolName ?? "a tool"}${req?.reason ? `: ${String(req.reason).slice(0, 200)}` : ""}`,
						toolName: req?.toolName ?? null
					};
					void runHooksSafe(matchAllEntries(config.hooks.Notification, "Notification", logOnce), {
						event: "Notification",
						cwd: resolveCwd(),
						payloadExtra: { message: notificationPayload.message, toolName: req?.toolName ?? null }
					});
					pushWebhook(config.webhook, notificationPayload, () => {});
				}
			} catch {
				/* observer only */
			}
			return next(); // always delegate: never claim the request
		});
	}, "approval/request listener registration")();

	/* ------------------------------------------------------------------ */
	/* UserPromptSubmit — via the agent/pre-step waterfall                 */
	/* ------------------------------------------------------------------ */

	safe(() => {
		ctx.on("agent/pre-step", async (payload, next) => {
			let decision;
			try {
				decision = await next();
			} catch (error) {
				if (error instanceof Error) {
					log("pre-step downstream failed:", error?.message ?? error);
				} else {
					// Cordis control-flow objects reject through the waterfall on turn
					// cancellation — e.g. AgentCancelCause {kind:"user"} when the human
					// interrupts or steers a running turn. Normal lifecycle noise, not
					// a hook failure; keep it terse and throttled.
					let shape = String(error?.kind ?? error);
					try {
						shape = JSON.stringify(error) ?? shape;
					} catch {
						/* non-serializable control-flow object */
					}
					logOnce(`pre-step interrupted by host (cause: ${shape})`);
				}
				throw error;
			}
			if (!decision || decision.kind === "reject") return decision;

			try {
				const config = currentConfig();

				// Detect fresh human prompts FIRST: even with no UserPromptSubmit
				// hook configured, new human input must re-arm the Stop-hook
				// continuation budget (steered messages are plugin-sourced and
				// never count as human input).
				const batch = decision.messages ?? payload?.messages ?? [];
				const fresh = [];
				for (const message of batch) {
					if (!message || message.role !== "user") continue;
					const sourceKind = message.source?.kind;
					if (sourceKind === "plugin") continue; // other plugins' injections are not prompts
					if (seenPrompts.has(message.id)) continue;
					seenPrompts.set(message.id, true);
					const text = messageTextOf(message);
					if (text) fresh.push(text);
				}
				while (seenPrompts.size > 5000) {
					const oldestId = seenPrompts.keys().next().value;
					seenPrompts.delete(oldestId);
				}
				if (fresh.length > 0) state.stopContinues?.delete(String(payload?.agent?.id ?? "?"));

				if (config.hooks.UserPromptSubmit.length === 0 && !config.webhook.url && !config.audit.enabled) {
					return decision;
				}

				if (fresh.length === 0) return decision;

				// Fresh human input re-arms the Stop-hook continuation budget.
				state.stopContinues?.delete(String(payload?.agent?.id ?? "?"));

				const agentId = payload?.agent?.id;
				const extraContexts = [];
				let vetoReason = null;

				for (const prompt of fresh) {
					auditRecord(currentConfig().audit, {
						kind: "prompt",
						time: new Date().toISOString(),
						sessionId: agentId ? String(agentId) : undefined,
						text: prompt.slice(0, 4000)
					});

					const results = await runHooksSafe(matchAllEntries(config.hooks.UserPromptSubmit, "UserPromptSubmit", logOnce), {
						event: "UserPromptSubmit",
						sessionId: agentId ? String(agentId) : undefined,
						cwd: resolveCwd(payload?.agent),
						payloadExtra: { prompt }
					});

					for (const result of results) {
						if (result.blocked && !vetoReason) vetoReason = result.reason || "blocked by UserPromptSubmit hook";
						if (result.additionalContext) extraContexts.push(userMessage(result.additionalContext, "UserPromptSubmit", payload?.agent?.session));
					}

					pushWebhook(
						config.webhook,
						{
							event: "UserPromptSubmit",
							sessionId: agentId ? String(agentId) : null,
							cwd: resolveCwd(payload?.agent),
							timestamp: new Date().toISOString(),
							prompt
						},
						() => {}
					);
				}

				if (vetoReason) {
					log(`UserPromptSubmit blocked: ${vetoReason}`);
					recordInterception(currentConfig().audit, {
						event: "UserPromptSubmit",
						source: "hooks",
						action: "deny",
						reason: vetoReason
					});
					interceptNotify?.(currentConfig(), "提示词被 UserPromptSubmit 钩子拦截");
					// Rejecting the step ends the turn as blocked — the CC "block prompt" semantic.
					return { kind: "reject" };
				}

				if (extraContexts.length > 0) {
					return {
						kind: "enter",
						messages: [...(decision.messages ?? []), ...extraContexts]
					};
				}
				return decision;
			} catch (error) {
				log("UserPromptSubmit stage failed (isolated):", error?.message ?? error);
				return decision;
			}
		});
	}, "pre-step listener registration")();

	/* ------------------------------------------------------------------ */
	/* Stop / PreCompact — via the persistent session event stream         */
	/* ------------------------------------------------------------------ */

	safe(() => {
		ctx.on("session/event", (session, event) => {
			try {
				const type = event?.type;
				if (type !== "turn/end" && type !== "compaction/start" && type !== "compaction/end") return;

				const config = currentConfig();
				const sid = sessionHeaderId(session);
				const cwd = session?.header?.cwd ?? resolveCwd();
				const now = new Date().toISOString();

				if (type === "turn/end") {
					const reason = event.data?.reason;
					const parentSession = session?.header?.parentSession;

					// Child sessions (subagents) end their turns here too; CC maps
					// that to a dedicated SubagentStop event instead of Stop.
					if (parentSession) {
						auditRecord(config.audit, {
							kind: "subagent-stop",
							time: now,
							sessionId: sid,
							parentSession: String(parentSession),
							reason: typeof reason === "string" ? reason : JSON.stringify(reason)?.slice(0, 200)
						});
						void runHooksSafe(matchAllEntries(config.hooks.SubagentStop, "SubagentStop", logOnce), {
							event: "SubagentStop",
							sessionId: sid,
							cwd,
							payloadExtra: { parentSession: String(parentSession), reason: reason ?? null }
						});
						pushWebhook(config.webhook, { event: "SubagentStop", sessionId: sid, cwd, timestamp: now, parentSession: String(parentSession), reason: reason ?? null }, () => {});
						return;
					}

					auditRecord(config.audit, {
						kind: "turn-stop",
						time: now,
						sessionId: sid,
						reason: typeof reason === "string" ? reason : JSON.stringify(reason)?.slice(0, 200)
					});
					if (config.notify.onStop) {
						notifyDesktop("DSH 回合结束", `会话 ${short(sid)} 已完成${reason ? `（${reason}）` : ""}`, { sound: config.notify.sound });
					}
					// Stop script hooks fire at the agent/turn-stopping boundary below
					// (before the turn closes), so a blocking hook can steer the same
					// turn back on — CC's "block and continue" semantic. This tail
					// event only audits / notifies / pushes the completed fact.
					pushWebhook(config.webhook, { event: "Stop", sessionId: sid, cwd, timestamp: now, reason: reason ?? null }, () => {});
					return;
				}

				if (type === "compaction/start") {
					auditRecord(config.audit, { kind: "compaction-start", time: now, sessionId: sid });
					void runHooksSafe(config.hooks.PreCompact, {
						event: "PreCompact",
						sessionId: sid,
						cwd,
						payloadExtra: { compactionId: event.data?.compactionId ?? null }
					});
					pushWebhook(config.webhook, { event: "PreCompact", sessionId: sid, cwd, timestamp: now }, () => {});
					return;
				}

				auditRecord(config.audit, {
					kind: "compaction-end",
					time: now,
					sessionId: sid,
					error: event.data?.error ? String(event.data.error).slice(0, 300) : undefined
				});
			} catch (error) {
				log("session/event handler failed (isolated):", error?.message ?? error);
			}
		});
	}, "session/event listener registration")();

	/* ------------------------------------------------------------------ */
	/* SessionStart                                                        */
	/* ------------------------------------------------------------------ */

	safe(() => {
		ctx.on("agent/session-start", safe((payload) => {
			const config = currentConfig();
			const agentId = payload?.agent?.id ? String(payload.agent.id) : undefined;
			state.stopContinues?.delete(String(payload?.agent?.id ?? "?"));
			auditRecord(config.audit, {
				kind: "session-start",
				time: new Date().toISOString(),
				sessionId: agentId,
				source: payload?.source
			});
			void runHooksSafe(config.hooks.SessionStart, {
				event: "SessionStart",
				sessionId: agentId,
				cwd: resolveCwd(payload?.agent),
				payloadExtra: { source: payload?.source ?? null }
			});
			pushWebhook(config.webhook, { event: "SessionStart", sessionId: agentId ?? null, cwd: resolveCwd(payload?.agent), timestamp: new Date().toISOString(), source: payload?.source ?? null }, () => {});
		}, "session-start handler"));
	}, "session-start listener registration")();

	/* ------------------------------------------------------------------ */
	/* Stop — at the agent/turn-stopping boundary so a blocking hook can    */
	/* steer the same turn back on (CC "block and continue" semantics).     */
	/* ------------------------------------------------------------------ */

	safe(() => {
		ctx.on("agent/turn-stopping", async (payload, next) => {
			try {
				await next();
			} catch {
				/* downstream control-flow noise must not block the boundary */
			}
			try {
				const agent = payload?.agent;
				const steer = typeof agent?.steer === "function" ? agent.steer.bind(agent) : null;
				if (!agent || !steer) return;
				// Subagent turns end via the SubagentStop event instead; CC Stop
				// semantics apply to the main agent only.
				if (agent.session?.header?.parentSession) return;

				const config = currentConfig();
				if (config.hooks.Stop.length === 0) return;

				const sid = agent.id ? String(agent.id) : undefined;
				const results = await runHooksSafe(config.hooks.Stop, {
					event: "Stop",
					sessionId: sid,
					cwd: resolveCwd(agent),
					payloadExtra: { stopHookActive: true }
				});
				const block = results.find((result) => result.blocked);
				if (!block) return;

				const reason = (block.reason || "blocked by Stop hook").slice(0, 2000);
				const key = String(agent.id ?? "?");
				const used = state.stopContinues.get(key) ?? 0;
				const max = config.stop.maxContinues;
				auditRecord(currentConfig().audit, {
					kind: "stop-block",
					time: new Date().toISOString(),
					sessionId: sid,
					reason,
					continued: used < max,
					continueCount: used
				});
				if (used >= max) {
					logOnce(`Stop 钩子连续阻断已达上限（${max} 次），放行回合结束，防失控`);
					return;
				}
				state.stopContinues.set(key, used + 1);
				steer(userMessage(`[hooks] Stop 钩子要求继续本轮工作：${reason}`.slice(0, 8000), "Stop-hook continue", agent.session));
				log(`Stop hook steered continuation ${used + 1}/${max}`);
			} catch (error) {
				logOnce(`agent/turn-stopping stage failed (isolated): ${error?.message ?? error}`);
			}
		});
	}, "agent/turn-stopping listener registration")();

	/* ------------------------------------------------------------------ */
	/* SessionEnd — the agent left the registry (live-to-cold)             */
	/* ------------------------------------------------------------------ */

	safe(() => {
		ctx.on("agent/disposed", safe((payload) => {
			const config = currentConfig();
			const agentId = payload?.agent?.id ? String(payload.agent.id) : undefined;
			state.stopContinues?.delete(String(payload?.agent?.id ?? "?"));
			auditRecord(config.audit, {
				kind: "session-end",
				time: new Date().toISOString(),
				sessionId: agentId
			});
			void runHooksSafe(matchAllEntries(config.hooks.SessionEnd, "SessionEnd", logOnce), {
				event: "SessionEnd",
				sessionId: agentId,
				cwd: resolveCwd(payload?.agent),
				payloadExtra: {}
			});
			pushWebhook(config.webhook, { event: "SessionEnd", sessionId: agentId ?? null, cwd: resolveCwd(payload?.agent), timestamp: new Date().toISOString() }, () => {});
		}, "agent/disposed handler"));
	}, "session-end listener registration")();
}

/**
 * All entries for lifecycle events. Matchers are meaningless without a tool
 * name; entries carrying one are reported once instead of silently ignored.
 */
function matchAllEntries(entries, event, logOnce) {
	for (const entry of entries ?? []) {
		if (entry?.matcher) logOnce?.(`hooks.${event}: 该事件没有工具名，条目 matcher "${entry.matcher}" 被忽略`);
	}
	return entries ?? [];
}

/** First plain-text block of a user message, best effort. */
function messageTextOf(message) {
	const content = message?.content;
	if (typeof content === "string") return content;
	if (Array.isArray(content)) {
		return content
			.filter((block) => block?.type === "text" && typeof block.text === "string")
			.map((block) => block.text)
			.join("\n")
			.trim();
	}
	return "";
}

function sessionHeaderId(session) {
	return session?.header?.id ? String(session.header.id) : session?.id ? String(session.id) : undefined;
}

function short(id) {
	const text = String(id ?? "");
	return text.length > 10 ? `${text.slice(0, 10)}…` : text;
}
