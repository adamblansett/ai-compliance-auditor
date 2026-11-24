import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../App';

function jsonResponse(payload: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

function createApiMock(options: { populated?: boolean } = {}) {
  const populated = options.populated ?? true;
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();

    if (url === '/api/v1/health') {
      return jsonResponse({
        status: 'ok',
        service: 'ai-compliance-auditor',
        app_name: 'AI Compliance & Regulatory Auditor',
        version: '0.1.0',
        environment: 'test',
        llm_provider: 'mock',
        database: 'ok',
      });
    }

    if (url === '/api/v1/overview') {
      return jsonResponse({
        posture: {
          overall_score_pct: populated ? 78.5 : 0.0,
          total_controls: populated ? 18 : 0,
          frameworks: [
            {
              framework: 'SOC2',
              total_controls: populated ? 6 : 0,
              passing: populated ? 4 : 0,
              failing: populated ? 2 : 0,
              warning: 0,
              waived: 0,
              not_evaluated: 0,
              score_pct: populated ? 75.0 : 0.0,
            },
            {
              framework: 'HIPAA',
              total_controls: populated ? 6 : 0,
              passing: populated ? 5 : 0,
              failing: populated ? 1 : 0,
              warning: 0,
              waived: 0,
              not_evaluated: 0,
              score_pct: populated ? 83.3 : 0.0,
            },
            {
              framework: 'GDPR',
              total_controls: populated ? 6 : 0,
              passing: populated ? 4 : 0,
              failing: populated ? 2 : 0,
              warning: 0,
              waived: 0,
              not_evaluated: 0,
              score_pct: populated ? 77.2 : 0.0,
            },
          ],
        },
        open_findings_by_severity: { critical: 2, high: 3, medium: 1, low: 0 },
        scan_runs_count: populated ? 5 : 0,
        pending_approvals_count: populated ? 1 : 0,
        evidence_bundles_count: populated ? 1 : 0,
        released_bundles_count: 0,
        audit_chain: {
          valid: true,
          total_events: populated ? 12 : 0,
          head_hash: 'abcdef1234567890abcdef1234567890',
          broken_sequence_no: null,
          message: 'All 12 audit events verified intact.',
        },
        dsar_metrics: {
          total: populated ? 3 : 0,
          open: populated ? 3 : 0,
          overdue: 0,
          legal_hold_blocked: populated ? 1 : 0,
          completed: 0,
        },
        active_legal_holds_count: populated ? 1 : 0,
        retention_metrics: {
          total: populated ? 4 : 0,
          compliant: populated ? 2 : 0,
          violations: populated ? 1 : 0,
          suspended: populated ? 1 : 0,
          exception_granted: 0,
        },
      });
    }

    if (url.startsWith('/api/v1/controls')) {
      return jsonResponse([
        {
          id: 'ctrl-1',
          control_code: 'SOC2-CC6.1',
          framework: 'SOC2',
          category: 'Logical Access Controls',
          title: 'Least-Privilege RBAC & Privileged MFA Enforcement',
          description: 'Enforce scoped roles and MFA.',
          severity: 'critical',
          scanner_domains_json: ['rbac'],
          required_rules_json: ['RBAC-001', 'RBAC-002'],
          owner_email: 'security@acme-compliance.local',
          status: 'failing',
          compliance_score: 33.3,
          evidence_summary: '1 passed, 2 failed',
          remediation_guidance: 'Remove wildcards.',
          waiver_expires_at: null,
          last_evaluated_at: '2026-11-24T12:00:00Z',
          created_at: '2026-11-24T12:00:00Z',
          updated_at: '2026-11-24T12:00:00Z',
        },
      ]);
    }

    if (url === '/api/v1/scanners/presets') {
      return jsonResponse([
        {
          preset_id: 'failing-staging-config',
          label: 'Failing Staging Env Config',
          target_name: 'staging-api-env',
          target_type: 'config',
          artifact_filename: 'staging.env',
          description: 'Sample staging config',
          content: 'DEBUG=true\nCORS_ORIGINS=*\n',
        },
      ]);
    }

    if (url === '/api/v1/scanners/runs') {
      return jsonResponse([]);
    }

    if (url === '/api/v1/scanners/findings') {
      return jsonResponse([]);
    }

    if (url === '/api/v1/scanners/scan' && init?.method === 'POST') {
      return jsonResponse(
        {
          id: 'scan-99',
          target_name: 'custom-service-config',
          target_type: 'config',
          artifact_filename: 'service.env',
          artifact_sha256: 'a'.repeat(64),
          artifact_preview: 'DEBUG=false',
          status: 'passed',
          total_checks: 4,
          passed_checks: 4,
          failed_checks: 0,
          warning_checks: 0,
          risk_score: 0,
          ai_summary: 'All config checks passed.',
          llm_provider: 'mock',
          triggered_by: 'officer@acme-compliance.local',
          created_at: '2026-11-24T12:00:00Z',
          findings: [],
        },
        201,
      );
    }

    if (url === '/api/v1/evidence/bundles') {
      return jsonResponse([
        {
          id: 'bundle-1',
          bundle_name: 'Q4 2026 Multi-Framework Readiness Package',
          frameworks_json: ['SOC2', 'HIPAA', 'GDPR'],
          period_start: '2026-10-25',
          period_end: '2026-11-24',
          status: 'pending_approval',
          item_count: 14,
          chain_head_hash: '1122334455667788',
          manifest_sha256: '9988776655443322',
          ai_attestation_summary: 'Compiled and ready for review.',
          compiled_by: 'officer@acme-compliance.local',
          approval_id: 'app-1',
          released_by: null,
          released_at: null,
          created_at: '2026-11-24T12:00:00Z',
        },
      ]);
    }

    if (url === '/api/v1/evidence/audit-events') {
      return jsonResponse([]);
    }

    if (url === '/api/v1/evidence/audit-events/verify') {
      return jsonResponse({
        valid: true,
        total_events: 12,
        head_hash: 'abcdef1234567890',
        broken_sequence_no: null,
        message: 'All 12 audit events verified intact.',
      });
    }

    if (url === '/api/v1/evidence/approvals') {
      return jsonResponse([
        {
          id: 'app-1',
          entity_type: 'evidence_bundle',
          entity_id: 'bundle-1',
          action_requested: 'release_audit_bundle',
          summary: 'Release Q4 2026 package to external auditors.',
          risk_level: 'high',
          payload_json: {},
          status: 'pending',
          requested_by: 'auditor@acme-compliance.local',
          decided_by: null,
          decision_notes: null,
          created_at: '2026-11-24T12:00:00Z',
          decided_at: null,
        },
      ]);
    }

    if (url === '/api/v1/privacy/dsars') {
      return jsonResponse([
        {
          id: 'dsar-1',
          reference_code: 'DSAR-2026-001',
          request_type: 'erasure',
          regulation: 'GDPR',
          subject_email: 'alex.morgan@example.com',
          subject_identifier_hash: 'hash',
          data_systems_json: ['billing_ledger'],
          status: 'blocked_by_legal_hold',
          due_date: '2026-12-24',
          legal_hold_blocked: true,
          blocking_hold_ids_json: ['LH-2026-001'],
          export_package_sha256: null,
          export_manifest_json: null,
          approval_id: null,
          notes: '',
          created_by: 'officer@acme-compliance.local',
          completed_at: null,
          created_at: '2026-11-24T12:00:00Z',
          updated_at: '2026-11-24T12:00:00Z',
        },
      ]);
    }

    if (url === '/api/v1/privacy/legal-holds') {
      return jsonResponse([]);
    }

    if (url === '/api/v1/privacy/retention-policies') {
      return jsonResponse([]);
    }

    if (url === '/api/v1/privacy/retention-exceptions') {
      return jsonResponse([]);
    }

    if (url.startsWith('/api/v1/seed/demo')) {
      return jsonResponse({
        seeded: true,
        controls_count: 18,
        scan_runs_count: 5,
        evidence_bundles_count: 1,
        dsars_count: 3,
        legal_holds_count: 1,
        retention_policies_count: 4,
        pending_approvals_count: 4,
        message: 'Seeded compliance demo dataset.',
      });
    }

    return jsonResponse({});
  });
}

describe('AI Compliance & Regulatory Auditor Workspace', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders executive posture, navigates all 6 tabs, switches roles, and executes scans', async () => {
    const mockFetch = createApiMock({ populated: true });
    vi.stubGlobal('fetch', mockFetch);

    render(<App />);

    expect(
      screen.getByRole('heading', { name: /AI Compliance & Regulatory Auditor/i }),
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/API Healthy \(mock\)/i)).toBeInTheDocument();
      expect(screen.getByText('78.5%')).toBeInTheDocument();
    });
    expect(screen.getByText('SOC2 Readiness')).toBeInTheDocument();
    expect(screen.getByText('HIPAA Readiness')).toBeInTheDocument();
    expect(screen.getByText('GDPR Readiness')).toBeInTheDocument();

    // Navigate to Controls
    fireEvent.click(screen.getByRole('button', { name: /Controls/i }));
    expect(await screen.findByText('SOC2-CC6.1')).toBeInTheDocument();

    // Navigate to Scanners and run a scan
    fireEvent.click(screen.getByRole('button', { name: /Scanners/i }));
    expect(await screen.findByText(/Failing Staging Env Config/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Run Compliance Scan/i }));
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/scanners/scan',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    // Navigate to Evidence & Audit
    fireEvent.click(screen.getByRole('button', { name: /Evidence & Audit/i }));
    expect(
      await screen.findByText(/Independent Tamper-Detection Verifier/i),
    ).toBeInTheDocument();

    // Navigate to Privacy & DSARs
    fireEvent.click(screen.getByRole('button', { name: /Privacy & DSARs/i }));
    expect(await screen.findByText('DSAR-2026-001')).toBeInTheDocument();
    expect(screen.getByText(/Blocked by Legal Hold\(s\): LH-2026-001/i)).toBeInTheDocument();

    // Navigate to Approvals and switch actor role
    fireEvent.click(screen.getByRole('button', { name: /Approvals/i }));
    expect(await screen.findByText('release_audit_bundle')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Actor Role'), {
      target: { value: 'auditor' },
    });
    await waitFor(() => {
      expect(
        screen.getByText(/Switched active actor to auditor@acme-compliance\.local/i),
      ).toBeInTheDocument();
    });
  });

  it('shows demo dataset loader CTA when workspace is empty', async () => {
    const mockFetch = createApiMock({ populated: false });
    vi.stubGlobal('fetch', mockFetch);

    render(<App />);

    expect(
      await screen.findByRole('heading', { name: /Initialize Compliance Audit Workspace/i }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Load Demo Dataset/i }));
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/seed/demo?reset=false',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });
});
