import { AlertTriangle, CheckCircle2, Database, FileLock2, Scale, ShieldAlert } from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import type { ApprovalRequestItem, OverviewSummary } from '../types/compliance';

interface OverviewViewProps {
  overview: OverviewSummary | null;
  approvals: ApprovalRequestItem[];
  onNavigate: (tab: string) => void;
  onLoadDemo: () => void;
  busy: boolean;
}

export function OverviewView({
  overview,
  approvals,
  onNavigate,
  onLoadDemo,
  busy,
}: OverviewViewProps) {
  const pendingApprovals = approvals.filter((a) => a.status === 'pending');

  if (!overview || overview.posture.total_controls === 0) {
    return (
      <section className="rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm">
        <Database className="mx-auto h-10 w-10 text-indigo-600" />
        <h2 className="mt-3 text-lg font-bold text-slate-900">
          Initialize Compliance Audit Workspace
        </h2>
        <p className="mx-auto mt-2 max-w-xl text-sm text-slate-600">
          Load the prebuilt SOC 2, HIPAA, and GDPR demo dataset—including 18 baseline controls,
          5 policy &amp; config scans, a hash-chained evidence package, DSARs with an active legal
          hold, and HITL approval gates.
        </p>
        <div className="mt-5 flex flex-wrap justify-center gap-3">
          <button
            type="button"
            disabled={busy}
            onClick={onLoadDemo}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50"
          >
            <Database className="h-4 w-4" />
            {busy ? 'Seeding Workspace...' : 'Load Demo Dataset'}
          </button>
          <button
            type="button"
            onClick={() => onNavigate('scanners')}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
          >
            Run Custom Policy Scan
          </button>
        </div>
      </section>
    );
  }

  const critCount = overview.open_findings_by_severity.critical || 0;
  const highCount = overview.open_findings_by_severity.high || 0;
  const totalOpenFindings = Object.values(overview.open_findings_by_severity).reduce(
    (acc, n) => acc + n,
    0,
  );

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Overall Compliance Score</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-900">
            {overview.posture.overall_score_pct.toFixed(1)}%
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Across {overview.posture.total_controls} mapped controls
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Open Scanner Findings</span>
            <ShieldAlert className="h-4 w-4 text-rose-600" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-900">{totalOpenFindings}</p>
          <p className="mt-1 text-xs text-slate-500">
            {critCount} critical · {highCount} high across {overview.scan_runs_count} scans
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Evidence &amp; Audit Chain</span>
            <FileLock2 className="h-4 w-4 text-indigo-600" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-900">
            {overview.audit_chain.valid ? 'Intact' : 'Tampered'}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {overview.audit_chain.total_events} chained events · {overview.evidence_bundles_count}{' '}
            bundle(s)
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500">
            <span>Privacy, DSARs &amp; Holds</span>
            <Scale className="h-4 w-4 text-amber-600" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-900">
            {overview.dsar_metrics.open} Open
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {overview.dsar_metrics.legal_hold_blocked} hold-blocked ·{' '}
            {overview.retention_metrics.violations} retention violation(s)
          </p>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        {overview.posture.frameworks.map((fw) => (
          <div
            key={fw.framework}
            className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900">{fw.framework} Readiness</h3>
              <span className="text-sm font-bold text-indigo-700">{fw.score_pct.toFixed(1)}%</span>
            </div>
            <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className={`h-full rounded-full ${
                  fw.score_pct >= 80
                    ? 'bg-emerald-500'
                    : fw.score_pct >= 50
                      ? 'bg-amber-500'
                      : 'bg-rose-500'
                }`}
                style={{ width: `${Math.min(100, Math.max(0, fw.score_pct))}%` }}
              />
            </div>
            <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-600">
              <span className="text-emerald-700">{fw.passing} passing</span>
              <span>·</span>
              <span className="text-rose-700">{fw.failing} failing</span>
              <span>·</span>
              <span className="text-amber-700">{fw.warning} warn</span>
              {fw.waived > 0 && (
                <>
                  <span>·</span>
                  <span className="text-indigo-700">{fw.waived} waived</span>
                </>
              )}
            </div>
          </div>
        ))}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Pending Human-in-the-Loop Approvals ({pendingApprovals.length})
            </h3>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('approvals')}
            className="text-xs font-semibold text-indigo-600 hover:underline"
          >
            Open Approval Queue →
          </button>
        </div>

        {pendingApprovals.length === 0 ? (
          <p className="mt-3 text-xs text-slate-500">
            No pending HITL compliance approvals.
          </p>
        ) : (
          <div className="mt-3 divide-y divide-slate-100">
            {pendingApprovals.slice(0, 5).map((item) => (
              <div
                key={item.id}
                className="flex flex-wrap items-center justify-between gap-3 py-2.5 text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <StatusBadge status={item.entity_type} />
                    <StatusBadge status={item.risk_level} />
                    <span className="font-semibold text-slate-800">{item.action_requested}</span>
                  </div>
                  <p className="text-slate-600">{item.summary}</p>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate('approvals')}
                  className="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-1.5 font-semibold text-indigo-700 hover:bg-indigo-100"
                >
                  Review Gate
                </button>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
