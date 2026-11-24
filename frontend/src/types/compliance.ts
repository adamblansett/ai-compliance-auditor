export type ActorRole = 'viewer' | 'auditor' | 'compliance_officer' | 'admin';

export interface ActorContext {
  email: string;
  role: ActorRole;
}

export interface HealthStatus {
  status: string;
  service: string;
  app_name: string;
  version: string;
  environment: string;
  llm_provider: string;
  database?: string;
}

export interface FrameworkPosture {
  framework: string;
  total_controls: number;
  passing: number;
  failing: number;
  warning: number;
  waived: number;
  not_evaluated: number;
  score_pct: number;
}

export interface PostureSummary {
  overall_score_pct: number;
  total_controls: number;
  frameworks: FrameworkPosture[];
}

export interface AuditChainVerify {
  valid: boolean;
  total_events: number;
  head_hash: string;
  broken_sequence_no: number | null;
  message: string;
}

export interface DsarMetrics {
  total: number;
  open: number;
  overdue: number;
  legal_hold_blocked: number;
  completed: number;
}

export interface RetentionMetrics {
  total: number;
  compliant: number;
  violations: number;
  suspended: number;
  exception_granted: number;
}

export interface OverviewSummary {
  posture: PostureSummary;
  open_findings_by_severity: Record<string, number>;
  scan_runs_count: number;
  pending_approvals_count: number;
  evidence_bundles_count: number;
  released_bundles_count: number;
  audit_chain: AuditChainVerify;
  dsar_metrics: DsarMetrics;
  active_legal_holds_count: number;
  retention_metrics: RetentionMetrics;
}

export interface SeedSummary {
  seeded: boolean;
  controls_count: number;
  scan_runs_count: number;
  evidence_bundles_count: number;
  dsars_count: number;
  legal_holds_count: number;
  retention_policies_count: number;
  pending_approvals_count: number;
  message: string;
}

export type FrameworkName = 'SOC2' | 'HIPAA' | 'GDPR';
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';
export type TargetType = 'config' | 'encryption' | 'logging' | 'rbac' | 'sop' | 'full_suite';

export interface ControlItem {
  id: string;
  control_code: string;
  framework: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  scanner_domains_json: string[];
  required_rules_json: string[];
  owner_email: string;
  status: string;
  compliance_score: number;
  evidence_summary: string;
  remediation_guidance: string;
  waiver_expires_at: string | null;
  last_evaluated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ControlCreateInput {
  control_code: string;
  framework: FrameworkName;
  category: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  scanner_domains: string[];
  required_rules: string[];
  owner_email: string;
  remediation_guidance: string;
}

export interface ScannerPreset {
  preset_id: string;
  label: string;
  target_name: string;
  target_type: TargetType;
  artifact_filename: string;
  description: string;
  content: string;
}

export interface ScanFindingItem {
  id: string;
  scan_run_id: string;
  rule_id: string;
  domain: string;
  severity: string;
  status: string;
  title: string;
  detail: string;
  remediation: string;
  mapped_controls_json: string[];
  evidence_snippet: string;
  evidence_hash: string;
  created_at: string;
}

export interface ScanRunItem {
  id: string;
  target_name: string;
  target_type: string;
  artifact_filename: string;
  artifact_sha256: string;
  artifact_preview: string;
  status: string;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warning_checks: number;
  risk_score: number;
  ai_summary: string;
  llm_provider: string;
  triggered_by: string;
  created_at: string;
  findings?: ScanFindingItem[];
}

export interface EvidenceBundleItem {
  id: string;
  bundle_name: string;
  frameworks_json: string[];
  period_start: string;
  period_end: string;
  status: string;
  item_count: number;
  chain_head_hash: string;
  manifest_sha256: string;
  ai_attestation_summary: string;
  compiled_by: string;
  approval_id: string | null;
  released_by: string | null;
  released_at: string | null;
  created_at: string;
  manifest_json?: Record<string, unknown>;
}

export interface EvidenceBundleExport {
  bundle_id: string;
  bundle_name: string;
  status: string;
  chain_head_hash: string;
  manifest_sha256: string;
  manifest: Record<string, unknown>;
}

export interface BundleVerifyResult {
  valid: boolean;
  item_count: number;
  chain_head_hash: string;
  manifest_sha256: string;
  broken_item_seq: number | null;
  errors: string[];
  message: string;
}

export interface AuditEventItem {
  id: string;
  sequence_no: number;
  event_type: string;
  actor_email: string;
  actor_role: string;
  entity_type: string;
  entity_id: string;
  action: string;
  details_json: Record<string, unknown>;
  prev_hash: string;
  event_hash: string;
  created_at: string;
}

export interface ApprovalRequestItem {
  id: string;
  entity_type: string;
  entity_id: string;
  action_requested: string;
  summary: string;
  risk_level: string;
  payload_json: Record<string, unknown>;
  status: string;
  requested_by: string;
  decided_by: string | null;
  decision_notes: string | null;
  created_at: string;
  decided_at: string | null;
}

export interface RedactionFinding {
  category: string;
  count: number;
  placeholder: string;
}

export interface PiiRedactResult {
  redacted_text: string;
  findings: RedactionFinding[];
  total_redactions: number;
}

export type DsarType = 'access' | 'erasure' | 'rectification' | 'portability' | 'restriction';
export type RegulationType = 'GDPR' | 'CCPA' | 'HIPAA';

export interface DsarRequestItem {
  id: string;
  reference_code: string;
  request_type: string;
  regulation: string;
  subject_email: string;
  subject_identifier_hash: string;
  data_systems_json: string[];
  status: string;
  due_date: string;
  legal_hold_blocked: boolean;
  blocking_hold_ids_json: string[];
  export_package_sha256: string | null;
  export_manifest_json: Record<string, unknown> | null;
  approval_id: string | null;
  notes: string;
  created_by: string;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface LegalHoldItem {
  id: string;
  hold_code: string;
  title: string;
  matter_reference: string;
  custodian_scope_json: string[];
  systems_scope_json: string[];
  reason: string;
  status: string;
  placed_by: string;
  released_by: string | null;
  placed_at: string;
  released_at: string | null;
}

export interface RetentionPolicyItem {
  id: string;
  policy_code: string;
  data_category: string;
  framework: string;
  system_name: string;
  retention_days: number;
  actual_oldest_record_days: number;
  purge_mechanism: string;
  encryption_at_rest: boolean;
  status: string;
  last_verified_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RetentionExceptionItem {
  id: string;
  policy_id: string;
  requested_retention_days: number;
  justification: string;
  expires_at: string;
  status: string;
  approval_id: string | null;
  requested_by: string;
  approved_by: string | null;
  created_at: string;
  updated_at: string;
}
