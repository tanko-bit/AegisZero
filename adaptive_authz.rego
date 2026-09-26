package aegiszero.authz

import future.keywords.in
import future.keywords.if

default allow = false
default action = "QUARANTINE_OR_DENY"
default reason = "Default Deny: Zero-Trust Evaluation"

# 1. Identity & Delegation Validation
valid_identity if {
    input.agent.spiffe_id != ""
    startswith(input.agent.spiffe_id, "spiffe://enterprise.corp/agent/")
    input.agent.session_token.expires_at > time.now_ns() / 1000000000
    input.agent.session_token.revocation_status == "ACTIVE"
}

# 2. Risk Score Evaluation
# Composite formula: R = sum(w_i * d_i)
weights := {
    "intent_drift": 0.25,
    "capability_criticality": 0.20,
    "blast_radius": 0.20,
    "context_sensitivity": 0.15,
    "trajectory_anomaly": 0.10,
    "environment_volatility": 0.10
}

composite_risk := sum([
    input.risk_dimensions.intent_drift * weights.intent_drift,
    input.risk_dimensions.capability_criticality * weights.capability_criticality,
    input.risk_dimensions.blast_radius * weights.blast_radius,
    input.risk_dimensions.context_sensitivity * weights.context_sensitivity,
    input.risk_dimensions.trajectory_anomaly * weights.trajectory_anomaly,
    input.risk_dimensions.environment_volatility * weights.environment_volatility
])

# 3. Dynamic Policy Actions
action := "ALLOW" if {
    valid_identity
    composite_risk < 30
    not is_forbidden_transition
}

action := "STEP_UP_CHALLENGE" if {
    valid_identity
    composite_risk >= 30
    composite_risk < 60
    not is_forbidden_transition
}

action := "HUMAN_APPROVAL_REQUIRED" if {
    valid_identity
    composite_risk >= 60
    composite_risk < 80
}

action := "HUMAN_APPROVAL_REQUIRED" if {
    valid_identity
    input.tool_call.financial_amount > 50000
}

action := "QUARANTINE_OR_DENY" if {
    not valid_identity
}

action := "QUARANTINE_OR_DENY" if {
    composite_risk >= 80
}

action := "QUARANTINE_OR_DENY" if {
    is_forbidden_transition
}

# 4. Trajectory Constraint Checks
is_forbidden_transition if {
    input.trajectory.last_tool in ["external_web_scrape", "read_untrusted_input"]
    input.tool_call.tool_name in ["execute_sql_query", "iam_assign_role", "execute_wire_transfer"]
}

is_forbidden_transition if {
    input.trajectory.consecutive_identical_tools > 5
}
