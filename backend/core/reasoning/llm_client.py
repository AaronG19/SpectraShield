import json
import os
import requests
from typing import Any, Dict, List, Optional
from core.logging import logger

# Schema definition for Gemini Structured Outputs
RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "verdict": {
            "type": "STRING",
            "description": "The analysis verdict: benign, suspicious, malicious, or requires_investigation."
        },
        "confidence": {
            "type": "NUMBER",
            "description": "Confidence score between 0.0 and 1.0."
        },
        "severity": {
            "type": "STRING",
            "description": "Assessed severity level: info, low, medium, high, critical."
        },
        "explanation": {
            "type": "STRING",
            "description": "Natural language summary of the investigation results and reasoning for security analysts."
        },
        "reasoning_steps": {
            "type": "ARRAY",
            "items": {"type": "STRING"},
            "description": "The sequential list of reasoning steps and logic analyzed."
        },
        "tool_calls": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "tool": {
                        "type": "STRING",
                        "description": "The exact name of the tool to invoke."
                    },
                    "args": {
                        "type": "OBJECT",
                        "description": "Key-value argument parameters to pass to the tool."
                    }
                },
                "required": ["tool"]
            },
            "description": "Intermediate tools to execute. Leave empty if a final verdict is reached."
        },
        "suggested_actions": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "action": {
                        "type": "STRING",
                        "description": "Action name: process_terminate, quarantine_file, host_isolate, alert_only."
                    },
                    "target": {
                        "type": "STRING",
                        "description": "Target process name, file path, IP, or empty if general host containment."
                    }
                },
                "required": ["action"]
            },
            "description": "containment/remediation actions recommended."
        }
    },
    "required": ["verdict", "confidence", "severity", "explanation"]
}


class GeminiClient:
    """HTTP-based API client for Google Gemini Developer API."""

    def __init__(self):
        try:
            import config
            self.api_key = getattr(config, "GEMINI_API_KEY", "")
            self.model = getattr(config, "LLM_MODEL", "gemini-3.5-flash")
            self.timeout = getattr(config, "LLM_API_TIMEOUT", 10)
            self.enabled = getattr(config, "AGENTIC_LLM_ENABLED", True)
        except ImportError:
            self.api_key = os.getenv("GEMINI_API_KEY", "")
            self.model = os.getenv("LLM_MODEL", "gemini-3.5-flash")
            self.timeout = int(os.getenv("LLM_API_TIMEOUT", "10"))
            self.enabled = os.getenv("AGENTIC_LLM_ENABLED", "true").lower() in ("true", "1")

    def is_configured(self) -> bool:
        return bool(self.enabled and self.api_key and self.api_key != "dummy_mock_key_for_testing")

    def query_agent(self, messages: List[Dict[str, Any]], system_instruction: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Query Gemini model with conversation history and structured schema."""
        if not self.api_key:
            logger.warning("Gemini Client queried but GEMINI_API_KEY is not set.")
            return None

        # Base URL
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        headers = {"Content-Type": "application/json"}

        # Construct contents block
        # messages should be in format: [{"role": "user"/"model", "parts": [{"text": "..."}]}]
        contents = []
        for msg in messages:
            role = msg.get("role", "user")
            # Gemini expects 'user' or 'model'
            if role == "assistant":
                role = "model"
            contents.append({
                "role": role,
                "parts": [{"text": msg.get("content", "")}]
            })

        body = {
            "contents": contents,
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
                "temperature": 0.1,  # Keep it deterministic for security analysis
            }
        }

        if system_instruction:
            body["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        try:
            logger.debug("Sending query to Gemini API", model=self.model, timeout=self.timeout)
            response = requests.post(url, headers=headers, json=body, timeout=self.timeout)
            
            if response.status_code != 200:
                logger.error(
                    "Gemini API returned error code",
                    status_code=response.status_code,
                    body=response.text[:500]
                )
                return None

            resp_data = response.json()
            candidates = resp_data.get("candidates", [])
            if not candidates:
                logger.warning("Gemini API response had no candidates", response=resp_data)
                return None

            text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            if not text:
                logger.warning("Gemini API candidate content was empty")
                return None

            try:
                parsed_json = json.loads(text.strip())
                return parsed_json
            except json.JSONDecodeError as exc:
                logger.error("Failed to parse JSON response from Gemini API text", text=text, error=str(exc))
                return None

        except requests.RequestException as exc:
            logger.warning("Network request to Gemini API failed", error=str(exc))
            return None
        except Exception as exc:
            logger.error("Unexpected error querying Gemini API", error=str(exc))
            return None


gemini_client = GeminiClient()
