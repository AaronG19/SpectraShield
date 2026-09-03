"""Reasoning Engine — structured analytical pipelines over normalized telemetry.

Pipeline per event:
  1. Context assembly      (agent profile, recent working-memory events, alert counts)
  2. Analytical tool calls (routed by event type, bounded by config)
  3. Signal aggregation    (indicator rules + severity + tool findings -> score)
  4. Verdict evaluation    (benign / suspicious / malicious / requires_investigation)
  5. Explanation generator (human-readable reasoning chain)
  6. Persistence          (reasoning_history via LongTermMemory)

In shadow mode the engine only logs decisions; it never creates alerts or
executes response actions.
"""
import asyncio
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.logging import logger
from core.reasoning.long_term_memory import LongTermMemory, long_term_memory
from core.reasoning.models import NormalizedEvent
from core.reasoning.perception import PerceptionEngine, perception_engine
from core.reasoning.tool_executor import ReasoningTool, ToolExecutor, get_tool_executor
from core.reasoning.working_memory import WorkingMemoryManager, working_memory as default_working_memory

SEVERITY_BASE_SCORE = {"info": 0, "low": 15, "medium": 35, "high": 60, "critical": 85}

# (feature_test, score, label) — independent evidence signals.
_INDICATOR_RULES: List[Tuple[Any, int, str]] = [
    (lambda f: f.get("shellcode_detected"), 90, "shellcode detected in memory"),
    (lambda f: f.get("tamper_detected"), 90, "agent tamper protection triggered"),
    (lambda f: f.get("threat_name"), 90, "named malware threat"),
    (lambda f: f.get("detection_type"), 85, "credential dumping indicator"),
    (lambda f: f.get("detection_reason"), 85, "NGAV detection reason present"),
    (lambda f: f.get("eventlog_alert"), 85, "event-log based fileless attack"),
    (lambda f: f.get("unknown_hash"), 75, "unknown file hash"),
    (lambda f: (f.get("reputation") or "").lower() in ("malicious", "bad", "malware"), 80, "negative threat-intel reputation"),
    (lambda f: int(f.get("connections", 0) or 0) >= 20, 75, "high beaconing connection count"),
    (lambda f: f.get("suspicious_patterns"), 80, "script monitor suspicious patterns"),
    (lambda f: f.get("sensitive_ports_hit"), 70, "sensitive port scan"),
    (lambda f: f.get("reason"), 70, "detection reason present"),
    (lambda f: f.get("is_anomaly"), 65, "behavioral anomaly"),
    (lambda f: f.get("changes_detected"), 60, "file integrity change"),
    (lambda f: f.get("is_auto_start"), 60, "registry autorun"),
    (lambda f: f.get("is_silent"), 55, "silent deployment"),
    (lambda f: f.get("blocked"), 50, "execution blocked"),
]

# Event type -> ordered list of (tool_name, kwargs_builder) routed in the pipeline.
_TOOL_ARG_BUILDERS: Dict[str, Any] = {}


def _ev(event: NormalizedEvent) -> Dict[str, Any]:
    return event.features


def _behavior_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    f = _ev(event)
    return {
        "process_name": f.get("process_name", ""),
        "cmdline": f.get("cmdline", ""),
        "parent_name": f.get("parent_name", ""),
        "file_path": f.get("file_path") or f.get("process_path", ""),
        "user": f.get("user", ""),
        "os_type": "windows",
        "agent_id": event.agent_id,
    }


def _network_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    f = _ev(event)
    return {
        "remote_ip": f.get("dst_ip") or f.get("destination_ip") or "",
        "remote_port": int(f.get("dst_port") or f.get("port") or 0),
        "process_name": f.get("process_name", ""),
        "agent_id": event.agent_id,
    }


def _registry_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    f = _ev(event)
    return {
        "key_path": f.get("key_path", ""),
        "value_name": f.get("value_name", ""),
        "new_value": f.get("new_value", ""),
        "change_type": f.get("change_type", "modified"),
        "agent_id": event.agent_id,
    }


def _risk_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    return {"event_type": event.event_type, "severity": event.severity, "agent_id": event.agent_id}


def _correlate_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    return {
        "event": {"event_type": event.event_type, "severity": event.severity, "features": event.features},
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "source": event.source,
    }


def _intel_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    f = _ev(event)
    indicator = f.get("indicator")
    if not indicator and f.get("iocs"):
        indicator = f["iocs"][0]
    if not indicator and f.get("dst_ip"):
        indicator = f["dst_ip"]
    return {"indicator": indicator or ""}


def _sample_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    return {"sample": {k: v for k, v in _ev(event).items() if not isinstance(v, (list, dict))},
            "agent_id": event.agent_id}


def _scheduled_kwargs(event: NormalizedEvent) -> Dict[str, Any]:
    return {"cmdline": _ev(event).get("cmdline", ""), "process_name": _ev(event).get("process_name", ""),
            "file_path": _ev(event).get("file_path") or _ev(event).get("process_path", ""),
            "os_type": "windows"}


_TOOL_ROUTES: Dict[str, List[Tuple[str, Any]]] = {
    "process_execution": [("analyze_behavior", _behavior_kwargs)],
    "pre_execution": [("analyze_behavior", _behavior_kwargs), ("detect_lolbin", _behavior_kwargs)],
    "process_tree": [("analyze_behavior", _behavior_kwargs), ("detect_suspicious_cmdline", lambda e: {"cmdline": _ev(e).get("cmdline", "")})],
    "behavioral_heuristics": [("check_baseline", lambda e: {"agent_id": e.agent_id, "metrics": {k: v for k, v in _ev(e).items() if isinstance(v, (int, float))}})],
    "registry_change": [("analyze_registry_change", _registry_kwargs), ("detect_registry_autorun", _registry_kwargs)],
    "silent_deployment": [("analyze_behavior", _behavior_kwargs), ("detect_persistence", _scheduled_kwargs)],
    "network_dpi": [("analyze_network_connection", _network_kwargs)],
    "c2_beaconing": [("analyze_network_connection", _network_kwargs), ("lookup_threat_intel", _intel_kwargs)],
    "port_scan": [],
    "lateral_movement": [("detect_lateral_movement", lambda e: {"cmdline": _ev(e).get("cmdline", "")})],
    "host_firewall": [],
    "threat_intel": [("lookup_threat_intel", _intel_kwargs)],
    "web_dns_filter": [("lookup_threat_intel", _intel_kwargs)],
    "script_monitor": [("detect_powershell_abuse", lambda e: {"cmdline": _ev(e).get("command", "")}),
                       ("detect_suspicious_cmdline", lambda e: {"cmdline": _ev(e).get("command", "")})],
    "credential_dumping": [],
    "ransomware_canary": [],
    "memory_scan": [],
    "fileless_detection": [],
    "offline_scan": [],
    "nextgen_av": [],
    "vulnerability_scan": [],
    "usb_disk": [],
    "misconfiguration": [],
    "file_integrity": [],
    "zero_day": [],
    "watchdog": [],
    "exploit_mitigation": [],
    "installation_visibility": [],
    "privilege_escalation": [],
    "shadow_it": [],
    "patch_scan": [],
    "asset_discovery": [],
    "software_inventory": [],
    "telemetry": [],
    "agent_monitor": [],
    "buffer_polish": [],
    "action_result": [],
    "user_behaviour": [],
}

# Event types whose verdict should trigger a response policy evaluation.
_RESPONSE_EVENT_TYPES = {
    "c2_beaconing", "lateral_movement", "ransomware_canary", "credential_dumping",
    "fileless_detection", "memory_scan", "offline_scan", "nextgen_av", "zero_day",
    "process_execution", "pre_execution",
}


def _map_verdict(score: float) -> str:
    if score >= 85:
        return "malicious"
    if score >= 60:
        return "suspicious"
    if score >= 35:
        return "requires_investigation"
    return "benign"


def _map_confidence(score: float) -> float:
    return round(min(0.99, max(0.3, 0.4 + abs(score - 50) / 100.0)), 3)


def _suggest_actions(event: NormalizedEvent, verdict: str, score: float) -> List[dict]:
    f = _ev(event)
    actions = []
    if verdict == "malicious":
        if f.get("dst_ip") or f.get("destination_ip") or f.get("scanner_ip"):
            actions.append({"action": "network_block", "target": f.get("dst_ip") or f.get("destination_ip") or f.get("scanner_ip"), "rationale": "Malicious network contact"})
        if f.get("process_name"):
            actions.append({"action": "process_terminate", "target": f.get("process_name"), "rationale": "Malicious process"})
        if f.get("file_path") or f.get("process_path"):
            actions.append({"action": "quarantine_file", "target": f.get("file_path") or f.get("process_path"), "rationale": "Malicious file"})
        actions.append({"action": "host_isolate", "target": "", "rationale": "High-confidence malicious activity"})
    elif verdict == "suspicious":
        actions.append({"action": "alert_only", "target": "", "rationale": "Suspicious activity flagged for analyst review"})
    else:
        actions.append({"action": "alert_only", "target": "", "rationale": "Requires investigation"})
    return actions


class ReasoningEngine:
    """Orchestrates perception, memory, tools and persistence into verdicts."""

    def __init__(self, perception: Optional[PerceptionEngine] = None,
                 working_memory: Optional[WorkingMemoryManager] = None,
                 tool_executor: Optional[ToolExecutor] = None,
                 memory: Optional[LongTermMemory] = None,
                 max_tool_calls: Optional[int] = None):
        self.perception = perception or perception_engine
        self.working_memory = working_memory or default_working_memory
        self.tool_executor = tool_executor or get_tool_executor()
        self.memory = memory or long_term_memory
        self.max_tool_calls = max_tool_calls

    # --- public entry points --------------------------------------------------

    async def ingest(self, event_type: str, agent_id: str, payload: Dict[str, Any],
                     event_id: str = "", db=None, shadow: bool = True) -> Optional[dict]:
        """Normalize, store in working memory, then evaluate."""
        try:
            from config import AGENTIC_MODE
        except ImportError:
            AGENTIC_MODE = False
        if not AGENTIC_MODE:
            return None

        event = self.perception.normalize(event_type, agent_id, payload, event_id=event_id)
        self.working_memory.push(event)
        return await self.evaluate(event, db=db, shadow=shadow)

    async def evaluate(self, event: NormalizedEvent, db=None, shadow: bool = True) -> dict:
        """Run the full reasoning pipeline for one normalized event."""
        from core.reasoning.llm_client import gemini_client
        if gemini_client.is_configured():
            try:
                return await self._evaluate_llm(event, db=db, shadow=shadow)
            except Exception as exc:
                logger.warning(
                    "LLM reasoning engine failed, falling back to legacy rule-based engine",
                    error=str(exc)
                )

        chain: List[dict] = []
        tool_calls: List[dict] = []
        actions_taken: List[dict] = []

        chain.append({
            "step": "context",
            "detail": self._describe_context(event),
            "timestamp": event.timestamp.isoformat(),
        })

        score, indicators = self._signal_score(event)

        for label in indicators:
            chain.append({"step": "signal", "detail": label})

        # Analytical tool calls.
        tools = self._select_tools(event)
        calls = 0
        for tool_name, kwargs_builder in tools:
            if self.max_tool_calls and calls >= self.max_tool_calls:
                break
            kwargs = kwargs_builder(event)
            result = await self.tool_executor.execute(tool_name, **kwargs)
            calls += 1
            tool_calls.append({"tool": tool_name, "args": kwargs, "result": result})
            score, _extra = self._fold_tool_result(score, tool_name, result)
            for label in _extra:
                chain.append({"step": "signal", "detail": label, "tool": tool_name})
            chain.append({"step": "tool", "detail": f"Invoked {tool_name}", "tool": tool_name})

        score = round(min(100.0, max(0.0, score)), 1)
        verdict = _map_verdict(score)
        confidence = _map_confidence(score)
        severity = _resolve_severity(event.severity, score)

        chain.append({"step": "verdict", "detail": f"Verdict {verdict} (score {score}, confidence {confidence})", "verdict": verdict})

        suggested = _suggest_actions(event, verdict, score)
        if verdict != "benign" and event.event_type in _RESPONSE_EVENT_TYPES and not shadow:
            resp = await self.tool_executor.execute(
                "evaluate_response",
                event={"event_type": event.event_type, "severity": severity, "score": score},
                agent_id=event.agent_id,
            )
            tool_calls.append({"tool": "evaluate_response", "args": {}, "result": resp})
            if resp.get("status") == "success" and resp["data"].get("count"):
                actions_taken.extend(resp["data"]["triggered"])
                chain.append({"step": "response", "detail": f"{resp['data']['count']} response policy(s) triggered", "tool": "evaluate_response"})

        result = {
            "event_id": event.id,
            "agent_id": event.agent_id,
            "event_type": event.event_type,
            "verdict": verdict,
            "confidence": confidence,
            "severity": severity,
            "score": score,
            "reasoning_chain": chain,
            "tool_calls": tool_calls,
            "actions_taken": actions_taken,
            "suggested_actions": suggested,
            "shadow": bool(shadow),
        }

        if db is not None:
            self.memory.log_reasoning(
                db, event.agent_id, event.id, verdict, confidence, severity,
                chain, actions_taken=actions_taken or suggested,
            )

        # Phase 3 — graduated takeover: RE becomes the authoritative decision-maker.
        if not shadow and db is not None and verdict != "benign":
            alert_id = self._persist_alert(db, event, result)
            if alert_id:
                result["alert_id"] = alert_id
            if _flag("AGENTIC_RESPONSE"):
                queued = self._queue_actions(db, event, result)
                if queued:
                    result["queued_actions"] = queued
            if _flag("AGENTIC_PLANNING"):
                plan = self._create_plan(db, event, result)
                if plan:
                    result["plan_id"] = plan["id"]
                    try:
                        from core.reasoning.planning_engine import planning_engine
                        await planning_engine.run_plan(db, plan["id"])
                    except Exception as e:
                        logger.warning("Failed to auto-run legacy reasoning plan", plan_id=plan["id"], error=str(e))

        logger.info(
            "Reasoning verdict",
            agent_id=event.agent_id, event_type=event.event_type,
            verdict=verdict, confidence=confidence, shadow=shadow,
        )
        return result

    async def _evaluate_llm(self, event: NormalizedEvent, db=None, shadow: bool = True) -> dict:
        """Run the LLM-based reasoning agent loop (ReAct)."""
        from core.reasoning.llm_client import gemini_client

        chain: List[dict] = []
        tool_calls: List[dict] = []
        actions_taken: List[dict] = []

        context = self._describe_context(event)
        chain.append({
            "step": "context",
            "detail": context,
            "timestamp": event.timestamp.isoformat(),
        })

        # List of available tools for LLM system instructions
        available = self.tool_executor.available_tools()
        tools_list_str = "\n".join([f"- Name: {t['name']}\n  Description: {t['description']}" for t in available])

        system_instruction = f"""You are an autonomous Cybersecurity Incident Reasoning Agent embedded inside an Endpoint Detection and Response (EDR) system.
Your job is to analyze security telemetry events from client endpoints and determine if they are benign, suspicious, malicious, or require further investigation.

You have access to a set of analysis tools. Before delivering a final verdict, you can call these tools to gather more context (such as process trees, baseline heuristics, IP reputations, registry changes).
You MUST execute tools when necessary to resolve ambiguity.

Available Tools:
{tools_list_str}

Strict Output Format:
Your response must be a single JSON object matching the JSON schema provided in the generation config. Do NOT wrap it in markdown block tags like ```json.
If you need to call a tool, return a non-empty `tool_calls` list (e.g. `[[{{"tool": "lookup_threat_intel", "args": {{"indicator": "8.8.8.8"}}}}]]`) and leave the `verdict` as "requires_investigation" or "suspicious". Once the tool output is provided back to you, continue reasoning.
If you have sufficient information to make a final decision, return an empty `tool_calls` list and set `verdict` to "benign", "suspicious", or "malicious".


Rules:
1. Always output a valid JSON object matching the requested schema.
2. Keep `confidence` high only when backed by tool evidence or clear indicators.
3. Provide recommended containment actions in `suggested_actions` if the verdict is malicious or suspicious.
"""

        messages = []
        tool_results = []
        max_loop = self.max_tool_calls or 5

        # Initialize the loop
        for loop_idx in range(max_loop):
            user_content = f"Evaluate event ID {event.id} from agent ID {event.agent_id}.\nEvent Type: {event.event_type}\nOriginal Severity: {event.severity}\nEvent Features: {json.dumps(event.features)}"
            if tool_results:
                user_content += "\n\nPrevious Tool Call Results:\n" + "\n".join([
                    f"- Tool '{r['tool']}': {json.dumps(r['result'])}" for r in tool_results
                ])
            else:
                user_content += f"\n\nPer-Agent Working Memory Context:\n{json.dumps(context)}"

            messages.append({"role": "user", "content": user_content})

            # Query the agent
            response = gemini_client.query_agent(messages, system_instruction=system_instruction)
            if response is None:
                raise RuntimeError("Failed to query Gemini API or parse JSON response.")

            # Record assistant response
            messages.append({"role": "assistant", "content": json.dumps(response)})

            # Accumulate intermediate reasoning steps
            for step in response.get("reasoning_steps", []):
                step_detail = {"step": "signal", "detail": step}
                if step_detail not in chain:
                    chain.append(step_detail)

            requested_tool_calls = response.get("tool_calls", [])
            if not requested_tool_calls:
                # No more tools needed; final verdict reached
                break

            # Execute the requested tools
            for tc in requested_tool_calls:
                tool_name = tc.get("tool")
                tool_args = tc.get("args") or {}
                
                # Check tool exists
                if not self.tool_executor.has(tool_name):
                    res = {"status": "error", "error": f"Tool '{tool_name}' not available."}
                else:
                    res = await self.tool_executor.execute(tool_name, **tool_args)

                tool_calls.append({"tool": tool_name, "args": tool_args, "result": res})
                tool_results.append({"tool": tool_name, "result": res})
                chain.append({
                    "step": "tool",
                    "detail": f"Invoked {tool_name} with args: {json.dumps(tool_args)}",
                    "tool": tool_name
                })

        # Process the final response
        verdict = response.get("verdict", "requires_investigation")
        confidence = float(response.get("confidence", 0.5))
        severity = response.get("severity", event.severity)
        explanation = response.get("explanation", "")
        reasoning_steps = response.get("reasoning_steps", [])
        suggested = response.get("suggested_actions", [])

        # Format suggested target format to ensure consistency
        formatted_suggested = []
        for action in suggested:
            name = action.get("action")
            target = action.get("target") or ""
            if name:
                formatted_suggested.append({
                    "action": name,
                    "target": target,
                    "rationale": explanation[:200]
                })

        # Build reasoning chain
        for step in reasoning_steps:
            step_detail = {"step": "signal", "detail": step}
            if step_detail not in chain:
                chain.append(step_detail)

        
        chain.append({
            "step": "verdict",
            "detail": f"AI Verdict {verdict} (confidence {confidence}): {explanation}",
            "verdict": verdict
        })

        # Translate confidence/severity/verdict into score for legacy consistency
        score = 50.0
        if verdict == "malicious":
            score = 90.0
        elif verdict == "suspicious":
            score = 65.0
        elif verdict == "requires_investigation":
            score = 40.0
        else:
            score = 15.0

        # Post-process actions
        if verdict != "benign" and event.event_type in _RESPONSE_EVENT_TYPES and not shadow:
            resp = await self.tool_executor.execute(
                "evaluate_response",
                event={"event_type": event.event_type, "severity": severity, "score": score},
                agent_id=event.agent_id,
            )
            tool_calls.append({"tool": "evaluate_response", "args": {}, "result": resp})
            if resp.get("status") == "success" and resp["data"].get("count"):
                actions_taken.extend(resp["data"]["triggered"])
                chain.append({
                    "step": "response",
                    "detail": f"{resp['data']['count']} response policy(s) triggered",
                    "tool": "evaluate_response"
                })

        result = {
            "event_id": event.id,
            "agent_id": event.agent_id,
            "event_type": event.event_type,
            "verdict": verdict,
            "confidence": confidence,
            "severity": severity,
            "score": score,
            "reasoning_chain": chain,
            "tool_calls": tool_calls,
            "actions_taken": actions_taken,
            "suggested_actions": formatted_suggested or [{"action": "alert_only", "target": "", "rationale": explanation[:200]}],
            "shadow": bool(shadow),
        }

        if db is not None:
            self.memory.log_reasoning(
                db, event.agent_id, event.id, verdict, confidence, severity,
                chain, actions_taken=actions_taken or formatted_suggested,
            )

        # Graduated takeover
        if not shadow and db is not None and verdict != "benign":
            alert_id = self._persist_alert(db, event, result)
            if alert_id:
                result["alert_id"] = alert_id
            if _flag("AGENTIC_RESPONSE"):
                queued = self._queue_actions(db, event, result)
                if queued:
                    result["queued_actions"] = queued
            if _flag("AGENTIC_PLANNING"):
                plan = self._create_plan(db, event, result)
                if plan:
                    result["plan_id"] = plan["id"]
                    try:
                        from core.reasoning.planning_engine import planning_engine
                        await planning_engine.run_plan(db, plan["id"])
                    except Exception as e:
                        logger.warning("Failed to auto-run AI reasoning plan", plan_id=plan["id"], error=str(e))

        logger.info(
            "AI Reasoning verdict",
            agent_id=event.agent_id, event_type=event.event_type,
            verdict=verdict, confidence=confidence, shadow=shadow,
        )
        return result

    # --- Phase 3 takeover helpers ---------------------------------------------

    def _persist_alert(self, db, event: NormalizedEvent, result: dict) -> Optional[str]:
        """Create or bump an Alert (fingerprint-deduped) for a non-benign verdict."""
        try:
            from models.alert import Alert
            fingerprint = _event_fingerprint(event)
            existing = db.query(Alert).filter(
                Alert.agent_id == event.agent_id,
                Alert.fingerprint == fingerprint,
                Alert.status == "open",
            ).first()
            details = {
                "verdict": result["verdict"],
                "confidence": result["confidence"],
                "score": result["score"],
                "reasoning_chain": result["reasoning_chain"][-5:],
                "tool_calls": [t["tool"] for t in result["tool_calls"]],
                "suggested_actions": result["suggested_actions"],
                "source": "reasoning_engine",
            }
            mitre = _mitre_for(event.event_type)
            if existing:
                existing.occurrence_count = (existing.occurrence_count or 1) + 1
                existing.last_seen_at = datetime.utcnow()
                existing.severity = result["severity"]
                existing.score = result["score"]
                existing.details = json.dumps(details, default=str)
                db.commit()
                return existing.id
            alert = Alert(
                agent_id=event.agent_id,
                title=_alert_title(event, result["verdict"]),
                description=f"Reasoning verdict {result['verdict']} with confidence {result['confidence']} (score {result['score']}).",
                severity=result["severity"],
                type=event.event_type or "malware",
                source="reasoning",
                score=result["score"],
                fingerprint=fingerprint,
                details=json.dumps(details, default=str),
                **mitre,
            )
            db.add(alert)
            db.commit()
            try:
                from core.reasoning.notifications import broadcast_alert_created
                broadcast_alert_created(alert.id, event.agent_id, result["severity"],
                                        event.event_type or "malware", result["verdict"])
            except Exception:
                pass
            return alert.id
        except Exception:
            db.rollback()
            return None

    def _queue_actions(self, db, event: NormalizedEvent, result: dict) -> List[dict]:
        """Queue auto-approved response actions, or flag the rest for analyst review."""
        try:
            from models.alert import PendingAction
            from config import REASONING_AUTO_EXECUTE_CONFIDENCE
        except Exception:
            REASONING_AUTO_EXECUTE_CONFIDENCE = 0.8
        queued = []
        for action in result.get("suggested_actions", []):
            name = action.get("action", "")
            if name in ("alert_only", ""):
                continue
            target = action.get("target", "")
            if result["confidence"] >= REASONING_AUTO_EXECUTE_CONFIDENCE:
                db.add(PendingAction(
                    agent_id=event.agent_id, action=name, target=target,
                    source="reasoning",
                ))
                queued.append({"action": name, "target": target, "status": "queued"})
            else:
                queued.append({"action": name, "target": target, "status": "pending_approval"})
        db.commit()
        return queued

    def _create_plan(self, db, event: NormalizedEvent, result: dict) -> Optional[dict]:
        """Kick off an execution plan for high-confidence malicious activity."""
        try:
            from core.reasoning.planning_engine import planning_engine
            return planning_engine.create_plan(
                db,
                plan_type="response" if result["verdict"] == "malicious" else "investigation",
                agent_id=event.agent_id,
                trigger_event_id=event.id,
                verdict=result["verdict"],
                severity=result["severity"],
                event_type=event.event_type,
                suggested_actions=result["suggested_actions"],
            )
        except Exception:
            return None

    # --- pipeline internals ---------------------------------------------------

    def _describe_context(self, event: NormalizedEvent) -> dict:
        recent = self.working_memory.get_recent_events(event.agent_id, window_seconds=3600)
        recent_types = {}
        for e in recent:
            recent_types[e.event_type] = recent_types.get(e.event_type, 0) + 1
        return {
            "agent_id": event.agent_id,
            "event_type": event.event_type,
            "events_in_window": len(recent),
            "recent_event_mix": recent_types,
        }

    def _signal_score(self, event: NormalizedEvent) -> Tuple[float, List[str]]:
        score = SEVERITY_BASE_SCORE.get(event.severity, 0)
        indicators: List[str] = []
        f = event.features
        for test, boost, label in _INDICATOR_RULES:
            try:
                if test(f):
                    score += boost
                    indicators.append(label)
            except (TypeError, ValueError):
                continue
        return float(score), indicators

    def _select_tools(self, event: NormalizedEvent) -> List[Tuple[str, Any]]:
        base = [("calculate_risk", _risk_kwargs)]
        routed = _TOOL_ROUTES.get(event.event_type, [])
        tools = list(routed) + base
        # Add ML anomaly scoring when meaningful numeric features exist.
        numeric = [v for v in _ev(event).values() if isinstance(v, (int, float)) and v not in (0, 0.0)]
        if numeric:
            tools.append(("predict_anomaly_iforest", _sample_kwargs))
            tools.append(("predict_anomaly_svm", _sample_kwargs))
        if event.event_type in _RESPONSE_EVENT_TYPES:
            tools.append(("correlate_event", _correlate_kwargs))
        return tools

    def _fold_tool_result(self, score: float, tool_name: str, result: dict) -> Tuple[float, List[str]]:
        """Bump the score based on high-signal tool findings."""
        extra: List[str] = []
        if result.get("status") != "success":
            return score, extra
        data = result.get("data")

        if tool_name in ("analyze_behavior", "analyze_registry_change", "analyze_network_connection"):
            findings = data.get("findings", []) if isinstance(data, dict) else []
            for finding in findings:
                risk = (finding or {}).get("risk", "").lower()
                if risk == "critical":
                    score += 25
                    extra.append(f"{tool_name}: critical finding {finding.get('finding_type', '')}")
                elif risk == "high":
                    score += 18
                    extra.append(f"{tool_name}: high finding {finding.get('finding_type', '')}")
                elif risk == "medium":
                    score += 10
            max_risk = data.get("max_risk_score", 0) if isinstance(data, dict) else 0
            score += min(20, float(max_risk or 0) * 0.25)

        elif tool_name in ("detect_lolbin", "detect_persistence", "detect_registry_autorun",
                           "detect_lateral_movement", "detect_powershell_abuse",
                           "detect_suspicious_cmdline"):
            findings = data or []
            if isinstance(findings, dict):
                findings = [findings] if findings.get("finding_type") else []
            for finding in findings:
                risk = (finding or {}).get("risk", "").lower()
                if risk == "critical":
                    score += 25
                elif risk == "high":
                    score += 18
                elif risk == "medium":
                    score += 10
                if finding and finding.get("finding_type"):
                    extra.append(f"{tool_name}: {finding.get('finding_type')}")

        elif tool_name == "lookup_threat_intel":
            rep = ((data or {}).get("reputation") or "").lower()
            if rep in ("malicious", "bad", "malware"):
                score += 30
                extra.append("threat-intel reputation is negative")
            elif rep == "suspicious":
                score += 15

        elif tool_name in ("predict_anomaly_iforest", "predict_anomaly_svm"):
            prediction = (data or {}).get("prediction")
            if isinstance(prediction, int) and prediction == 1:
                score += 12
                extra.append(f"{tool_name}: flagged anomaly")

        elif tool_name == "check_baseline":
            if (data or {}).get("is_anomalous"):
                score += 15
                extra.append("baseline check flagged anomaly")

        elif tool_name == "calculate_risk":
            total = (data or {}).get("total_score", 0)
            score = max(score, float(total or 0))

        return score, extra


def _resolve_severity(base_severity: str, score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return base_severity if base_severity in ("info", "low") else "low"


def _flag(name: str) -> bool:
    try:
        import config
        return bool(getattr(config, name, False))
    except ImportError:
        return False


def _mitre_for(event_type: str) -> dict:
    try:
        from constants.mitre import MITRE_ATTACK_MAP, get_mitre_tactic_name, get_mitre_technique_name
        mapping = MITRE_ATTACK_MAP.get(event_type, {})
        if not mapping:
            mapping = MITRE_ATTACK_MAP.get("threat_intel", {})
        return {
            "mitre_tactic_id": mapping.get("tactic_id", ""),
            "mitre_tactic_name": get_mitre_tactic_name(mapping.get("tactic_id", "")),
            "mitre_technique_id": mapping.get("technique_id", ""),
            "mitre_technique_name": get_mitre_technique_name(mapping.get("technique_id", "")),
        }
    except Exception:
        return {}


def _event_fingerprint(event: NormalizedEvent) -> str:
    salient = []
    for k in ("process_name", "cmdline", "dst_ip", "destination_ip", "scanner_ip",
              "target_ip", "file_path", "file_hash", "indicator", "detection_type",
              "key_path", "value_name", "threat_type", "reason", "command"):
        v = event.features.get(k)
        if v not in (None, ""):
            salient.append(f"{k}={v}")
    key = f"{event.agent_id}|{event.event_type}|{','.join(sorted(salient))}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def _alert_title(event: NormalizedEvent, verdict: str) -> str:
    names = {
        "process_execution": "Process Execution",
        "pre_execution": "Pre-Execution Block",
        "c2_beaconing": "C2 Beaconing",
        "lateral_movement": "Lateral Movement",
        "port_scan": "Port Scan",
        "credential_dumping": "Credential Dumping",
        "ransomware_canary": "Ransomware Canary Triggered",
        "fileless_detection": "Fileless Attack",
        "memory_scan": "Memory Injection",
        "registry_change": "Registry Change",
        "behavioral_heuristics": "Behavioral Anomaly",
        "threat_intel": "Threat Intelligence Match",
        "network_dpi": "Network DPI Alert",
        "script_monitor": "Suspicious Script",
        "zero_day": "Potential Zero-Day",
        "file_integrity": "File Integrity Change",
        "web_dns_filter": "Web/DNS Filter Block",
        "silent_deployment": "Silent Deployment",
    }
    base = names.get(event.event_type, event.event_type.replace("_", " ").title())
    return f"{base} — {verdict.title()} (Agentic)"


reasoning_engine = ReasoningEngine()
