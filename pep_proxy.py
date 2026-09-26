"""
AegisZero Deterministic Policy Enforcement Point (PEP) Proxy
Python FastAPI / LangChain / LangGraph Interceptor
"""
import time
import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel

class ToolCallRequest(BaseModel):
    spiffe_id: str
    session_token: str
    tool_name: str
    parameters: Dict[str, Any]
    original_mission: str

class PolicyEnforcementPoint:
    def __init__(self, opa_url: str = "http://localhost:8181/v1/data/aegiszero/authz"):
        self.opa_url = opa_url

    def intercept(self, req: ToolCallRequest) -> Dict[str, Any]:
        # 1. Compute deterministic risk dimensions
        is_sql = "sql" in req.tool_name.lower() or "transfer" in req.tool_name.lower()
        param_str = str(req.parameters).lower()
        has_injection = "drop" in param_str or "select * from vault" in param_str

        risk_dimensions = {
            "intent_drift": 95 if has_injection else 10,
            "capability_criticality": 85 if is_sql else 20,
            "blast_radius": 90 if "amount" in req.parameters and req.parameters["amount"] > 50000 else 15,
            "context_sensitivity": 90 if has_injection else 25,
            "trajectory_anomaly": 80 if has_injection else 5,
            "environment_volatility": 15
        }

        # 2. Query OPA Policy Decision Point (PDP)
        opa_input = {
            "input": {
                "agent": {
                    "spiffe_id": req.spiffe_id,
                    "session_token": {
                        "expires_at": int(time.time()) + 1800,
                        "revocation_status": "ACTIVE"
                    }
                },
                "tool_call": {
                    "tool_name": req.tool_name,
                    "parameters": req.parameters,
                    "financial_amount": req.parameters.get("amount", 0)
                },
                "risk_dimensions": risk_dimensions,
                "trajectory": {
                    "last_tool": "start",
                    "consecutive_identical_tools": 1
                }
            }
        }

        resp = requests.post(self.opa_url, json=opa_input)
        decision = resp.json().get("result", {})
        action = decision.get("action", "QUARANTINE_OR_DENY")

        if action == "ALLOW":
            return {"status": "SUCCESS", "action": "ALLOW", "message": "Policy permitted execution"}
        elif action == "STEP_UP_CHALLENGE":
            attenuated = dict(req.parameters)
            if "limit" in attenuated:
                attenuated["limit"] = min(attenuated["limit"], 20)
            return {"status": "ATTENUATED", "action": action, "attenuated_parameters": attenuated}
        elif action == "HUMAN_APPROVAL_REQUIRED":
            return {"status": "PENDING_APPROVAL", "action": action, "queue_id": "hitl_q_0991"}
        else:
            return {"status": "QUARANTINED", "action": action, "alert": "Critical security violation"}
