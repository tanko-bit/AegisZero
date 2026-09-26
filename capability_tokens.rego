package aegiszero.capability

import future.keywords.in
import future.keywords.if

default token_valid = false

# Capability Token (C-Token) Verification
token_valid if {
    c_token := input.capability_token
    c_token.revocation_status == "ACTIVE"
    c_token.expires_at > time.now_ns() / 1000000000
    
    # Verify target resource match
    glob.match(c_token.target_resource, ["/"], input.tool_call.resource)
    
    # Verify allowed verbs
    input.tool_call.verb in c_token.caveats.allowed_verbs
    
    # Verify parameter bounds
    validate_parameter_caveats(c_token.caveats, input.tool_call.parameters)
}

validate_parameter_caveats(caveats, params) if {
    not caveats.max_records_allowed
}

validate_parameter_caveats(caveats, params) if {
    caveats.max_records_allowed
    params.limit <= caveats.max_records_allowed
}
