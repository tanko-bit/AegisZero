# AegisZero: Enterprise Agent Secure Deployment Audit Matrix

**Date:** 2026-09-16
**Framework Alignments:** NIST AI RMF 1.0, OWASP Top 10 for LLMs, ISO/IEC 42001, CISA Zero Trust

| Pillar | Criterion | Target Threshold | Status | Criticality |
|---|---|---|---|---|
| IDENTITY_ATTESTATION | Cryptographic Workload Identity & SPIFFE SVID | 100% of deployed agents | ✅ PASS | CRITICAL |
| IDENTITY_ATTESTATION | Prompt & Model Provenance Integrity Attestation | Signed manifest present | ✅ PASS | HIGH |
| IDENTITY_ATTESTATION | Cryptographic Delegation Chain & Intent Ceiling | Valid signature chain with max risk ceiling | ✅ PASS | CRITICAL |
| IDENTITY_ATTESTATION | Ephemeral Session Tokens (TTL <= 30 mins) | <= 1800 seconds | ✅ PASS | HIGH |
| DYNAMIC_RISK | Multidimensional Real-Time Scoring (6 Dimensions) | 100% tool calls scored pre-execution | ✅ PASS | CRITICAL |
| DYNAMIC_RISK | Semantic Intent Drift Attestation Boundary | Drift sensitivity >= 85% | ✅ PASS | CRITICAL |
| DYNAMIC_RISK | Dynamic Risk Policy Banding (4 Thresholds) | 4 bands implemented | ✅ PASS | HIGH |
| PEP_ISOLATION | Strict Separation: Untrusted Reasoning vs Deterministic PEP | Zero direct network egress from agent container | ✅ PASS | CRITICAL |
| PEP_ISOLATION | Capability-Based Access Control (Macaroons / C-Tokens) | Zero ambient privilege / 100% C-token verified | ✅ PASS | CRITICAL |
| PEP_ISOLATION | Strict Schema & Parameter Boundary Validation | 100% schema compliance | ✅ PASS | HIGH |
| TRAJECTORY_GOVERNANCE | Cumulative Blast Radius Accumulation Tracking | Cumulative state tracking active | ✅ PASS | CRITICAL |
| TRAJECTORY_GOVERNANCE | Autonomous Loop & Velocity Spike Detection | Max 5 consecutive identical tool cycles allowed | ✅ PASS | HIGH |
| TRAJECTORY_GOVERNANCE | Forbidden Tool Transition Constraints | Transition graph enforced | ✅ PASS | HIGH |
| HITL_RESILIENCE | Dual-Custody Human Approval for High-Impact Mutations | Dual-custody gate active for critical operations | ✅ PASS | CRITICAL |
| HITL_RESILIENCE | Dynamic Parameter Attenuation for Borderline Actions | Attenuation rewrite rules supported | ✅ PASS | MEDIUM |
| HITL_RESILIENCE | Instant Agent Quarantine Kill-Switch (MTTR < 100ms) | Containment latency < 100ms | ✅ PASS | CRITICAL |
| HITL_RESILIENCE | Tamper-Evident Cryptographic Audit Ledger | 100% execution events hash-chained | ✅ PASS | HIGH |

## Pillar Breakdown & Remediation

### [CRIT-ID-01] Cryptographic Workload Identity & SPIFFE SVID
- **Description:** Every autonomous enterprise agent must possess a unique, verifiable SPIFFE ID with X.509 SVID or JWT token, bound to its workload namespace.
- **NIST AI RMF:** GOVERN 1.1, MAP 1.1
- **OWASP LLM:** LLM06: Excessive Agency
- **ISO 42001:** A.6.2.2 (AI System Traceability)
- **Remediation Guide:** Configure SPIRE Workload API sidecar to mint SVIDs dynamically to agent containers.

### [CRIT-ID-02] Prompt & Model Provenance Integrity Attestation
- **Description:** Foundation model digest and system prompt manifest must be hashed (SHA-256) and signed at container deployment time to detect tampered instructions.
- **NIST AI RMF:** MAP 2.1, MEASURE 2.4
- **OWASP LLM:** LLM05: Supply Chain Vulnerabilities
- **ISO 42001:** A.8.4 (Supply Chain & AI Models)
- **Remediation Guide:** Enforce CI/CD signature step using Cosign/Sigstore before spinning up agent runtimes.

### [CRIT-ID-03] Cryptographic Delegation Chain & Intent Ceiling
- **Description:** Downstream worker and sub-agents must carry a cryptographically signed delegation chain originating from an authorized human employee or certified orchestrator.
- **NIST AI RMF:** GOVERN 1.2, MANAGE 1.1
- **OWASP LLM:** LLM06: Excessive Agency
- **ISO 42001:** A.6.1.3 (Roles and Responsibilities)
- **Remediation Guide:** Mandate parent orchestrator signs task delegation tokens with strict risk ceiling.

### [CRIT-ID-04] Ephemeral Session Tokens (TTL <= 30 mins)
- **Description:** Agents must not hold persistent long-lived API tokens. Session tokens must have strict TTL <= 30 minutes with single-flight nonces.
- **NIST AI RMF:** MEASURE 2.1
- **OWASP LLM:** LLM08: Autonomous Loops & Persistence
- **ISO 42001:** A.9.2 (Access Control)
- **Remediation Guide:** Configure AegisZero token minter to enforce 1800s maximum lifetime.

### [CRIT-RISK-01] Multidimensional Real-Time Scoring (6 Dimensions)
- **Description:** Every proposed tool execution must be evaluated across all 6 risk dimensions (Intent Drift, Tool Criticality, Blast Radius, Context Sensitivity, Trajectory Anomaly, Environment Volatility).
- **NIST AI RMF:** MEASURE 1.1, MEASURE 2.2
- **OWASP LLM:** LLM01, LLM02, LLM06
- **ISO 42001:** A.5.2 (AI Risk Assessment)
- **Remediation Guide:** Integrate the AegisZero composite scoring equation inside the PEP interceptor.

### [CRIT-RISK-02] Semantic Intent Drift Attestation Boundary
- **Description:** Mathematical or LLM-based vector cosine distance between the original approved human mission and the tool invocation payload must be computed.
- **NIST AI RMF:** MANAGE 2.3 (AI Anomaly Detection)
- **OWASP LLM:** LLM01: Prompt Injection
- **ISO 42001:** A.7.2 (AI Monitoring)
- **Remediation Guide:** Enable the server-side Gemini Intent Attestation API or local embedding attestation engine.

### [CRIT-RISK-03] Dynamic Risk Policy Banding (4 Thresholds)
- **Description:** Policy engine must enforce 4 discrete response tiers: ALLOW (<30), STEP_UP/ATTENUATE (30-59), HITL (60-79), QUARANTINE (>=80).
- **NIST AI RMF:** MANAGE 1.2, GOVERN 2.1
- **OWASP LLM:** LLM06: Excessive Agency
- **ISO 42001:** A.6.2 (Governance and Strategy)
- **Remediation Guide:** Verify OPA policy adaptive_authz.rego enforces all 4 action bands.

### [CRIT-PEP-01] Strict Separation: Untrusted Reasoning vs Deterministic PEP
- **Description:** The agent reasoning loop (LLM) must never have direct network or database access. All actions pass through a deterministic proxy that holds credentials.
- **NIST AI RMF:** GOVERN 1.3, MANAGE 2.2
- **OWASP LLM:** LLM01: Prompt Injection, LLM02: Insecure Output
- **ISO 42001:** A.8.2 (Data and Model Security)
- **Remediation Guide:** Deploy the AegisZero PEP sidecar and restrict agent pod egress via Kubernetes NetworkPolicy.

### [CRIT-PEP-02] Capability-Based Access Control (Macaroons / C-Tokens)
- **Description:** Tool access must be governed by attenuated cryptographic capability tokens with embedded caveats (resource URI, allowed verbs, max records, max dollar amount).
- **NIST AI RMF:** GOVERN 1.2, MANAGE 2.1
- **OWASP LLM:** LLM06: Excessive Agency
- **ISO 42001:** A.9.1 (Access Control Policy)
- **Remediation Guide:** Transition from role-based IAM to AegisZero C-Token caveat verification in PEP.

### [CRIT-PEP-03] Strict Schema & Parameter Boundary Validation
- **Description:** Every tool argument must be strictly validated against formal JSON Schema specifications before invocation. Unexpected parameters must trigger rejection.
- **NIST AI RMF:** MEASURE 2.6
- **OWASP LLM:** LLM02: Insecure Output Handling
- **ISO 42001:** A.8.3 (System Verification)
- **Remediation Guide:** Implement strict JSON Schema validator in PEP middleware pipeline.

### [CRIT-TRAJ-01] Cumulative Blast Radius Accumulation Tracking
- **Description:** The PEP must track aggregate impact over time (e.g. cumulative financial sum, total customer records read across steps) rather than evaluating steps in isolation.
- **NIST AI RMF:** MEASURE 2.5, MANAGE 2.4
- **OWASP LLM:** LLM08: Excessive Automation / Resource Exhaustion
- **ISO 42001:** A.7.3 (Monitoring and Logging)
- **Remediation Guide:** Ensure Trajectory Monitor state store maintains sliding window session blast radius counters.

### [CRIT-TRAJ-02] Autonomous Loop & Velocity Spike Detection
- **Description:** Detect recursive tool invocation cycles, denial-of-wallet loops, and abnormal step frequencies exceeding velocity thresholds.
- **NIST AI RMF:** MANAGE 2.3
- **OWASP LLM:** LLM08: Infinite Autonomous Loops
- **ISO 42001:** A.7.2 (AI Operations)
- **Remediation Guide:** Enable cyclic graph detection in TrajectoryEngine.

### [CRIT-TRAJ-03] Forbidden Tool Transition Constraints
- **Description:** Enforce state machine transition graph rules (e.g., Reading unverified external internet content CANNOT be immediately followed by internal credential or financial transfer APIs).
- **NIST AI RMF:** GOVERN 1.3, MAP 2.3
- **OWASP LLM:** LLM01: Prompt Injection, LLM06: Excessive Agency
- **ISO 42001:** A.8.3 (Control of AI Changes)
- **Remediation Guide:** Define forbidden tool transition matrix in AegisZero policy rules.

### [CRIT-HITL-01] Dual-Custody Human Approval for High-Impact Mutations
- **Description:** Actions exceeding enterprise thresholds (financial mutations > $50k, table drop, bulk PII export > 500 records) must block and require dual human signatures.
- **NIST AI RMF:** GOVERN 1.2, MANAGE 1.3
- **OWASP LLM:** LLM06: Excessive Agency
- **ISO 42001:** A.6.1.4 (Human Oversight)
- **Remediation Guide:** Configure HITL approval service with multi-approver role requirements.

### [CRIT-HITL-02] Dynamic Parameter Attenuation for Borderline Actions
- **Description:** Rather than simple binary rejection, the system must support dynamic capability attenuation (e.g., automatically clamping record limits, stripping PII flags, converting writes to dry-runs).
- **NIST AI RMF:** MANAGE 2.1
- **OWASP LLM:** LLM06: Excessive Agency
- **ISO 42001:** A.8.2 (Security Architecture)
- **Remediation Guide:** Implement Rego-based parameter mutation in PEP response handler.

### [CRIT-HITL-03] Instant Agent Quarantine Kill-Switch (MTTR < 100ms)
- **Description:** A single API call or policy violation at risk level CRITICAL must immediately revoke all ephemeral tokens and terminate the agent session across the fleet.
- **NIST AI RMF:** MANAGE 2.4 (Incident Response)
- **OWASP LLM:** LLM08: Rogue Agent Containment
- **ISO 42001:** A.10.1 (Incident Management)
- **Remediation Guide:** Connect PEP to Redis/In-Memory token revocation cache with sub-millisecond propagation.

### [CRIT-HITL-04] Tamper-Evident Cryptographic Audit Ledger
- **Description:** All tool calls, risk scoring breakdowns, PEP enforcement decisions, and human approvals must be logged into an append-only, SHA-256 hash-chained audit trail.
- **NIST AI RMF:** GOVERN 1.4, MEASURE 2.7
- **OWASP LLM:** LLM02: Auditability
- **ISO 42001:** A.7.3 (Event Logging)
- **Remediation Guide:** Enable hash-chained event streaming to enterprise SIEM/Splunk.

