import { useState } from 'react';
import { Check, ShieldCheck, X } from 'lucide-react';
import { decideApproval } from '../api/client';
import { StatusBadge } from './StatusBadge';
import type { ActorContext, ApprovalRequestItem } from '../types/compliance';

interface ApprovalsViewProps {
  actor: ActorContext;
  approvals: ApprovalRequestItem[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

export function ApprovalsView({
  actor,
  approvals,
  onRefresh,
  onNotify,
}: ApprovalsViewProps) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [notesById, setNotesById] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);

  const canDecide = actor.role === 'compliance_officer' || actor.role === 'admin';

  const filtered = approvals.filter((item) => {
    if (statusFilter !== 'all' && item.status !== statusFilter) return false;
    if (typeFilter !== 'all' && item.entity_type !== typeFilter) return false;
    return true;
  });

  async function handleDecide(approvalId: string, decision: 'approved' | 'rejected') {
    setBusyId(approvalId);
    try {
      const notes = notesById[approvalId] || `${decision} by ${actor.email}`;
      const res = await decideApproval(actor, approvalId, decision, notes);
      onNotify(`Approval '${res.action_requested}' marked ${res.status}.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Approval decision failed', true);
      await onRefresh();
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-5">
      <section className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-bold text-slate-900">
            Human-in-the-Loop Compliance Approval Gates ({filtered.length})
          </h2>
        </div>

        <div className="flex flex-wrap gap-2">
          <select
            aria-label="Filter Approvals by Status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs"
          >
            <option value="all">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
          </select>

          <select
            aria-label="Filter Approvals by Gate Type"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs"
          >
            <option value="all">All Gate Types</option>
            <option value="control_waiver">Control Waiver</option>
            <option value="evidence_bundle">Evidence Bundle Release</option>
            <option value="dsar_fulfillment">DSAR Fulfillment</option>
            <option value="retention_exception">Retention Exception</option>
          </select>
        </div>
      </section>

      {!canDecide && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs font-medium text-amber-800">
          Current role is <strong>{actor.role}</strong>. Switch to Compliance Officer or Admin to
          approve or reject HITL gates.
        </div>
      )}

      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white p-6 text-center text-xs text-slate-500">
            No approval requests match the selected filter.
          </div>
        ) : (
          filtered.map((item) => (
            <article
              key={item.id}
              className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge status={item.entity_type} />
                    <StatusBadge status={item.risk_level} />
                    <StatusBadge status={item.status} />
                    <span className="text-xs font-bold text-slate-900">
                      {item.action_requested}
                    </span>
                  </div>
                  <p className="text-xs text-slate-700">{item.summary}</p>
                  <p className="text-[11px] text-slate-500">
                    Requested by: {item.requested_by}
                    {item.decided_by ? ` · Decided by: ${item.decided_by}` : ''}
                  </p>
                </div>
              </div>

              {item.status === 'pending' ? (
                <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
                  <input
                    type="text"
                    placeholder="Decision rationale / officer sign-off note..."
                    value={notesById[item.id] || ''}
                    onChange={(e) =>
                      setNotesById((prev) => ({ ...prev, [item.id]: e.target.value }))
                    }
                    className="min-w-[220px] flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
                  />
                  <button
                    type="button"
                    disabled={!canDecide || busyId === item.id}
                    onClick={() => handleDecide(item.id, 'approved')}
                    className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                  >
                    <Check className="h-3.5 w-3.5" />
                    Approve
                  </button>
                  <button
                    type="button"
                    disabled={!canDecide || busyId === item.id}
                    onClick={() => handleDecide(item.id, 'rejected')}
                    className="inline-flex items-center gap-1 rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
                  >
                    <X className="h-3.5 w-3.5" />
                    Reject
                  </button>
                </div>
              ) : (
                item.decision_notes && (
                  <p className="mt-2 rounded bg-slate-50 px-3 py-1.5 text-xs text-slate-600">
                    Decision Notes: {item.decision_notes}
                  </p>
                )
              )}
            </article>
          ))
        )}
      </div>
    </div>
  );
}
