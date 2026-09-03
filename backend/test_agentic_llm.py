import asyncio
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add backend to path if running directly
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.reasoning.models import NormalizedEvent
from core.reasoning.reasoning_engine import ReasoningEngine
from core.reasoning.perception import perception_engine
from core.reasoning.working_memory import working_memory


class TestAgenticLLM(unittest.TestCase):

    def setUp(self):
        # Create a fresh reasoning engine with mocked dependencies
        self.perception = perception_engine
        self.working_memory = working_memory
        self.tool_executor = MagicMock()
        
        # Mock tool executor to return standard tool call outcomes
        self.tool_executor.has.return_value = True
        self.tool_executor.execute = MagicMock(side_effect=self._mock_tool_execution)
        self.tool_executor.available_tools.return_value = [
            {"name": "lookup_threat_intel", "description": "Lookup IP reputations", "category": "intel", "version": "1.0"},
            {"name": "check_baseline", "description": "Check behavioral anomalies", "category": "heuristics", "version": "1.0"}
        ]
        
        self.engine = ReasoningEngine(
            perception=self.perception,
            working_memory=self.working_memory,
            tool_executor=self.tool_executor,
            max_tool_calls=3
        )
        
        # Clear working memory
        self.working_memory._agent_contexts = {}

    async def _mock_tool_execution(self, tool_name, **kwargs):
        # Return mock success data based on the tool
        return {
            "status": "success",
            "tool": tool_name,
            "data": {"reputation": "malicious", "findings": [{"risk": "high", "finding_type": "c2_hit"}]}
        }

    @patch("core.reasoning.llm_client.gemini_client")
    def test_llm_react_loop_and_verdict(self, mock_gemini):
        # Set up mock responses for ReAct loop:
        # Step 1: LLM wants to check threat intel
        # Step 2: LLM delivers final malicious verdict
        mock_gemini.is_configured.return_value = True
        mock_responses = [
            # Response 1: Requests tool call
            {
                "verdict": "requires_investigation",
                "confidence": 0.6,
                "severity": "medium",
                "explanation": "Event requires context enrichment via threat intel.",
                "reasoning_steps": ["Telemetry arrived", "Checking IP reputation"],
                "tool_calls": [{"tool": "lookup_threat_intel", "args": {"indicator": "8.8.8.8"}}],
                "suggested_actions": []
            },
            # Response 2: Final verdict after consuming tool result
            {
                "verdict": "malicious",
                "confidence": 0.95,
                "severity": "critical",
                "explanation": "The indicator is listed as malicious in threat intel feeds.",
                "reasoning_steps": ["IP reputation analyzed", "Confirming C2 command channel"],
                "tool_calls": [],
                "suggested_actions": [{"action": "process_terminate", "target": "malicious.exe"}]
            }
        ]
        
        # Setup mock side effect to return responses in order
        mock_gemini.query_agent.side_effect = mock_responses

        # Construct a mock event
        event = NormalizedEvent(
            event_id="test-event-uuid",
            agent_id="test-agent-uuid",
            event_type="c2_beaconing",
            severity="medium",
            features={"dst_ip": "8.8.8.8"}
        )

        # Execute reasoning evaluation
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self.engine.evaluate(event, db=None, shadow=True))
        finally:
            loop.close()

        # Assertions
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["confidence"], 0.95)
        self.assertEqual(result["severity"], "critical")
        
        # Verify tool calls were triggered on the tool executor
        self.tool_executor.execute.assert_called_with("lookup_threat_intel", indicator="8.8.8.8")
        
        # Verify the reasoning chain shows both steps
        steps = [step.get("detail") for step in result["reasoning_chain"] if step.get("step") == "signal"]
        self.assertIn("Telemetry arrived", steps)
        self.assertIn("Confirming C2 command channel", steps)
        
        # Verify suggested actions
        self.assertEqual(len(result["suggested_actions"]), 1)
        self.assertEqual(result["suggested_actions"][0]["action"], "process_terminate")
        self.assertEqual(result["suggested_actions"][0]["target"], "malicious.exe")

    @patch("core.reasoning.llm_client.gemini_client")
    def test_fallback_to_rules_on_llm_failure(self, mock_gemini):
        # Configure Gemini client to fail (return None or raise exception)
        mock_gemini.is_configured.return_value = True
        mock_gemini.query_agent.return_value = None  # Mock failure

        # Construct event
        event = NormalizedEvent(
            event_id="test-event-uuid-2",
            agent_id="test-agent-uuid",
            event_type="c2_beaconing",
            severity="high",
            features={"connections": 25, "shellcode_detected": True}
        )

        # Run evaluation (should fallback to legacy rules and succeed)
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self.engine.evaluate(event, db=None, shadow=True))
        finally:
            loop.close()

        # Check legacy rule verdict (high connections + shellcode should trigger malicious/suspicious)
        self.assertEqual(result["verdict"], "malicious")
        self.assertGreaterEqual(result["score"], 85)
        
        # Confirm that tool executor was called for legacy checks
        # Legacy select_tools would execute calculate_risk, correlate_event, predict_anomaly_iforest/svm
        self.assertTrue(self.tool_executor.execute.called)


if __name__ == "__main__":
    unittest.main()
