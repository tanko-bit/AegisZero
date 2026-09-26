/**
 * AegisZero Deterministic Policy Enforcement Point (PEP) Middleware
 * Express / Node.js Reference Implementation
 */
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

export interface ToolInvocationRequest {
  agentPassport: {
    spiffeId: string;
    sessionTokenId: string;
  };
  toolName: string;
  parameters: Record<string, unknown>;
  originalMission: string;
}

export class PolicyEnforcementPoint {
  private opaUrl: string;

  constructor(opaUrl = 'http://localhost:8181/v1/data/aegiszero/authz') {
    this.opaUrl = opaUrl;
  }

  // Intercepts tool calls before external systems execute them
  public async interceptToolCall(req: ToolInvocationRequest): Promise<{
    allowed: boolean;
    action: string;
    attenuatedParams?: Record<string, unknown>;
    riskScore: number;
    reason: string;
  }> {
    // 1. Calculate dynamic risk dimensions
    const riskDimensions = this.evaluateRiskDimensions(req);
    
    // 2. Query OPA Policy Engine
    const opaPayload = {
      input: {
        agent: {
          spiffe_id: req.agentPassport.spiffeId,
          session_token: {
            token_id: req.agentPassport.sessionTokenId,
            expires_at: Math.floor(Date.now() / 1000) + 1800,
            revocation_status: 'ACTIVE',
          },
        },
        tool_call: {
          tool_name: req.toolName,
          parameters: req.parameters,
        },
        risk_dimensions: riskDimensions,
      },
    };

    const response = await fetch(this.opaUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opaPayload),
    });
    const { result } = await response.json();

    if (result.action === 'ALLOW') {
      return { allowed: true, action: 'ALLOW', riskScore: result.composite_risk, reason: 'Risk evaluated within acceptable bounds' };
    } else if (result.action === 'STEP_UP_CHALLENGE') {
      // Attenuate parameters dynamically
      const attenuated = { ...req.parameters, limit: Math.min(Number(req.parameters.limit || 100), 20) };
      return { allowed: true, action: 'STEP_UP_CHALLENGE', attenuatedParams: attenuated, riskScore: result.composite_risk, reason: 'Capability attenuated' };
    } else if (result.action === 'HUMAN_APPROVAL_REQUIRED') {
      return { allowed: false, action: 'HUMAN_APPROVAL_REQUIRED', riskScore: result.composite_risk, reason: 'High blast radius requires human dual custody' };
    } else {
      // Quarantine session
      return { allowed: false, action: 'QUARANTINE_OR_DENY', riskScore: result.composite_risk, reason: 'Risk threshold breached. Session quarantined.' };
    }
  }

  private evaluateRiskDimensions(req: ToolInvocationRequest) {
    // Deterministic calculation
    const hasDrop = JSON.stringify(req.parameters).toLowerCase().includes('drop');
    return {
      intent_drift: hasDrop ? 95 : 15,
      capability_criticality: req.toolName.includes('sql') || req.toolName.includes('wire') ? 85 : 20,
      blast_radius: req.parameters.amount ? 80 : 15,
      context_sensitivity: 40,
      trajectory_anomaly: 10,
      environment_volatility: 10,
    };
  }
}
