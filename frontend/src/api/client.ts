import type {
  ActorContext,
  ApprovalRequestItem,
  AuditChainVerify,
  AuditEventItem,
  BundleVerifyResult,
  ControlCreateInput,
  ControlItem,
  DsarRequestItem,
  DsarType,
  EvidenceBundleExport,
  EvidenceBundleItem,
  FrameworkName,
  HealthStatus,
  LegalHoldItem,
  OverviewSummary,
  PiiRedactResult,
  RegulationType,
  RetentionExceptionItem,
  RetentionPolicyItem,
  ScanFindingItem,
  ScanRunItem,
  ScannerPreset,
  SeedSummary,
  TargetType,
} from '../types/compliance';

export class ApiClientError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
  }
}

async function requestJson<T>(
  path: string,
  actor: ActorContext,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('X-Actor-Email', actor.email);
  headers.set('X-Actor-Role', actor.role);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = (await response.json()) as {
        detail?: string | { message?: string };
      };
      if (typeof payload.detail === 'string') {
        message = payload.detail;
      } else if (payload.detail && typeof payload.detail.message === 'string') {
        message = payload.detail.message;
      }
    } catch {
      // ignore non-JSON error body
    }
    throw new ApiClientError(message, response.status);
  }
  return (await response.json()) as T;
}

export async function fetchHealth(): Promise<HealthStatus> {
  const response = await fetch('/api/v1/health');
  if (!response.ok) {
    throw new ApiClientError('API health check failed', response.status);
  }
  return (await response.json()) as HealthStatus;
}

export function fetchOverview(actor: ActorContext): Promise<OverviewSummary> {
  return requestJson<OverviewSummary>('/api/v1/overview', actor);
}

export function seedDemoData(actor: ActorContext, reset = false): Promise<SeedSummary> {
  return requestJson<SeedSummary>(`/api/v1/seed/demo?reset=${reset}`, actor, {
    method: 'POST',
  });
}

export function fetchControls(
  actor: ActorContext,
  framework?: string,
  status?: string,
): Promise<ControlItem[]> {
  const params = new URLSearchParams();
  if (framework) params.set('framework', framework);
  if (status) params.set('status', status);
  const qs = params.toString();
  return requestJson<ControlItem[]>(`/api/v1/controls${qs ? `?${qs}` : ''}`, actor);
}

export function seedControlCatalog(
  actor: ActorContext,
): Promise<{ created: number; total: number; message: string }> {
  return requestJson<{ created: number; total: number; message: string }>(
    '/api/v1/controls/seed-catalog',
    actor,
    { method: 'POST' },
  );
}

export function createControl(
  actor: ActorContext,
  payload: ControlCreateInput,
): Promise<ControlItem> {
  return requestJson<ControlItem>('/api/v1/controls', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function evaluateControls(
  actor: ActorContext,
  framework?: string,
): Promise<ControlItem[]> {
  const qs = framework ? `?framework=${encodeURIComponent(framework)}` : '';
  return requestJson<ControlItem[]>(`/api/v1/controls/evaluate${qs}`, actor, {
    method: 'POST',
  });
}

export function requestControlWaiver(
  actor: ActorContext,
  controlId: string,
  justification: string,
  waiverDays: number,
): Promise<{ control_id: string; approval_id: string; message: string }> {
  return requestJson<{ control_id: string; approval_id: string; message: string }>(
    `/api/v1/controls/${controlId}/waiver`,
    actor,
    {
      method: 'POST',
      body: JSON.stringify({ justification, waiver_days: waiverDays }),
    },
  );
}

export function fetchScannerPresets(actor: ActorContext): Promise<ScannerPreset[]> {
  return requestJson<ScannerPreset[]>('/api/v1/scanners/presets', actor);
}

export function fetchScanRuns(actor: ActorContext): Promise<ScanRunItem[]> {
  return requestJson<ScanRunItem[]>('/api/v1/scanners/runs', actor);
}

export function fetchScanFindings(actor: ActorContext): Promise<ScanFindingItem[]> {
  return requestJson<ScanFindingItem[]>('/api/v1/scanners/findings', actor);
}

export function runInlineScan(
  actor: ActorContext,
  payload: {
    target_name: string;
    target_type: TargetType;
    artifact_filename: string;
    content: string;
    auto_evaluate_controls?: boolean;
  },
): Promise<ScanRunItem> {
  return requestJson<ScanRunItem>('/api/v1/scanners/scan', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function uploadScanArtifact(
  actor: ActorContext,
  file: File,
  targetName: string,
  targetType: TargetType,
  autoEvaluate = true,
): Promise<ScanRunItem> {
  const form = new FormData();
  form.append('file', file);
  form.append('target_name', targetName);
  form.append('target_type', targetType);
  form.append('auto_evaluate_controls', String(autoEvaluate));
  return requestJson<ScanRunItem>('/api/v1/scanners/upload', actor, {
    method: 'POST',
    body: form,
  });
}

export function fetchBundles(actor: ActorContext): Promise<EvidenceBundleItem[]> {
  return requestJson<EvidenceBundleItem[]>('/api/v1/evidence/bundles', actor);
}

export function compileBundle(
  actor: ActorContext,
  payload: {
    bundle_name: string;
    frameworks: FrameworkName[];
    period_start?: string;
    period_end?: string;
  },
): Promise<EvidenceBundleItem> {
  return requestJson<EvidenceBundleItem>('/api/v1/evidence/bundles/compile', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function verifyBundleById(
  actor: ActorContext,
  bundleId: string,
): Promise<BundleVerifyResult> {
  return requestJson<BundleVerifyResult>(`/api/v1/evidence/bundles/${bundleId}/verify`, actor);
}

export function exportBundle(
  actor: ActorContext,
  bundleId: string,
): Promise<EvidenceBundleExport> {
  return requestJson<EvidenceBundleExport>(`/api/v1/evidence/bundles/${bundleId}/export`, actor);
}

export function verifyBundlePayload(
  actor: ActorContext,
  payload: {
    manifest: Record<string, unknown>;
    expected_manifest_sha256?: string;
    expected_chain_head?: string;
  },
): Promise<BundleVerifyResult> {
  return requestJson<BundleVerifyResult>('/api/v1/evidence/bundles/verify-payload', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function fetchAuditEvents(actor: ActorContext): Promise<AuditEventItem[]> {
  return requestJson<AuditEventItem[]>('/api/v1/evidence/audit-events', actor);
}

export function verifyAuditChain(actor: ActorContext): Promise<AuditChainVerify> {
  return requestJson<AuditChainVerify>('/api/v1/evidence/audit-events/verify', actor);
}

export function fetchApprovals(actor: ActorContext): Promise<ApprovalRequestItem[]> {
  return requestJson<ApprovalRequestItem[]>('/api/v1/evidence/approvals', actor);
}

export function decideApproval(
  actor: ActorContext,
  approvalId: string,
  decision: 'approved' | 'rejected',
  notes: string,
): Promise<ApprovalRequestItem> {
  return requestJson<ApprovalRequestItem>(
    `/api/v1/evidence/approvals/${approvalId}/decide`,
    actor,
    {
      method: 'POST',
      body: JSON.stringify({ decision, notes }),
    },
  );
}

export function redactPiiText(actor: ActorContext, text: string): Promise<PiiRedactResult> {
  return requestJson<PiiRedactResult>('/api/v1/evidence/pii/redact', actor, {
    method: 'POST',
    body: JSON.stringify({ text }),
  });
}

export function fetchDsars(actor: ActorContext): Promise<DsarRequestItem[]> {
  return requestJson<DsarRequestItem[]>('/api/v1/privacy/dsars', actor);
}

export function createDsar(
  actor: ActorContext,
  payload: {
    request_type: DsarType;
    regulation: RegulationType;
    subject_email: string;
    data_systems: string[];
    notes: string;
  },
): Promise<DsarRequestItem> {
  return requestJson<DsarRequestItem>('/api/v1/privacy/dsars', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function prepareDsarFulfillment(
  actor: ActorContext,
  dsarId: string,
): Promise<DsarRequestItem> {
  return requestJson<DsarRequestItem>(
    `/api/v1/privacy/dsars/${dsarId}/prepare-fulfillment`,
    actor,
    { method: 'POST' },
  );
}

export function fetchLegalHolds(actor: ActorContext): Promise<LegalHoldItem[]> {
  return requestJson<LegalHoldItem[]>('/api/v1/privacy/legal-holds', actor);
}

export function createLegalHold(
  actor: ActorContext,
  payload: {
    title: string;
    matter_reference: string;
    custodian_scope: string[];
    systems_scope: string[];
    reason: string;
  },
): Promise<LegalHoldItem> {
  return requestJson<LegalHoldItem>('/api/v1/privacy/legal-holds', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function releaseLegalHold(
  actor: ActorContext,
  holdId: string,
  reason: string,
): Promise<LegalHoldItem> {
  return requestJson<LegalHoldItem>(`/api/v1/privacy/legal-holds/${holdId}/release`, actor, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export function fetchRetentionPolicies(actor: ActorContext): Promise<RetentionPolicyItem[]> {
  return requestJson<RetentionPolicyItem[]>('/api/v1/privacy/retention-policies', actor);
}

export function createRetentionPolicy(
  actor: ActorContext,
  payload: {
    policy_code: string;
    data_category: string;
    framework: FrameworkName;
    system_name: string;
    retention_days: number;
    actual_oldest_record_days: number;
    purge_mechanism: string;
    encryption_at_rest: boolean;
  },
): Promise<RetentionPolicyItem> {
  return requestJson<RetentionPolicyItem>('/api/v1/privacy/retention-policies', actor, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function verifyRetentionPolicies(actor: ActorContext): Promise<RetentionPolicyItem[]> {
  return requestJson<RetentionPolicyItem[]>('/api/v1/privacy/retention-policies/verify', actor, {
    method: 'POST',
  });
}

export function fetchRetentionExceptions(
  actor: ActorContext,
): Promise<RetentionExceptionItem[]> {
  return requestJson<RetentionExceptionItem[]>('/api/v1/privacy/retention-exceptions', actor);
}

export function requestRetentionException(
  actor: ActorContext,
  policyId: string,
  payload: {
    requested_retention_days: number;
    justification: string;
    expires_at: string;
  },
): Promise<RetentionExceptionItem> {
  return requestJson<RetentionExceptionItem>(
    `/api/v1/privacy/retention-policies/${policyId}/exceptions`,
    actor,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
  );
}
