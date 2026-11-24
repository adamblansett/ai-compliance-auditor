import { FormEvent, useState } from 'react';
import { Plus, RefreshCw, ShieldQuestion } from 'lucide-react';
import {
  createControl,
  evaluateControls,
  requestControlWaiver,
  seedControlCatalog,
} from '../api/client';
import { StatusBadge } from './StatusBadge';
import type {
  ActorContext,
  ControlItem,
  FrameworkName,
  SeverityLevel,
} from '../types/compliance';

interface ControlsViewProps {
  actor: ActorContext;
  controls: ControlItem[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

export function ControlsView({
  actor,
  controls,
  onRefresh,
  onNotify,
}: ControlsViewProps) {
  const [frameworkFilter, setFrameworkFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [busy, setBusy] = useState(false);

  const [showCreate, setShowCreate] = useState(false);
  const [controlCode, setControlCode] = useState('');
  const [framework, setFramework] = useState<FrameworkName>('SOC2');
  const [category, setCategory] = useState('Access & Security');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<SeverityLevel>('high');
  const [requiredRules, setRequiredRules] = useState('CFG-001, CFG-002');
  const [ownerEmail, setOwnerEmail] = useState('security@acme-compliance.local');

  const [waiverControlId, setWaiverControlId] = useState<string | null>(null);
  const [waiverDays, setWaiverDays] = useState(30);
  const [waiverReason, setWaiverReason] = useState('');

  const canWrite = actor.role !== 'viewer';

  const filtered = controls.filter((c) => {
    if (frameworkFilter !== 'ALL' && c.framework !== frameworkFilter) return false;
    if (statusFilter !== 'all' && c.status !== statusFilter) return false;
    return true;
  });

  async function handleSeedCatalog() {
    setBusy(true);
    try {
      const res = await seedControlCatalog(actor);
      onNotify(res.message);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Catalog seed failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleEvaluateAll() {
    setBusy(true);
    try {
      const targetFw = frameworkFilter === 'ALL' ? undefined : frameworkFilter;
      const updated = await evaluateControls(actor, targetFw);
      onNotify(`Evaluated ${updated.length} control(s) against latest scanner & privacy evidence.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Evaluation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateControl(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const rules = requiredRules
        .split(',')
        .map((r) => r.trim().toUpperCase())
        .filter(Boolean);
      const created = await createControl(actor, {
        control_code: controlCode,
        framework,
        category,
        title,
        description,
        severity,
        scanner_domains: ['config'],
        required_rules: rules,
        owner_email: ownerEmail,
        remediation_guidance: 'Remediate failed mapped rules and re-run evaluation.',
      });
      onNotify(`Registered custom control ${created.control_code}.`);
      setControlCode('');
      setTitle('');
      setDescription('');
      setShowCreate(false);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Control creation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleSubmitWaiver(controlId: string) {
    if (!waiverReason.trim()) {
      onNotify('Provide a risk justification before requesting a waiver.', true);
      return;
    }
    setBusy(true);
    try {
      const res = await requestControlWaiver(actor, controlId, waiverReason, waiverDays);
      onNotify(res.message);
      setWaiverControlId(null);
      setWaiverReason('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Waiver request failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <section className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          {(['ALL', 'SOC2', 'HIPAA', 'GDPR'] as const).map((fw) => (
            <button
              key={fw}
              type="button"
              onClick={() => setFrameworkFilter(fw)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                frameworkFilter === fw
                  ? 'bg-indigo-600 text-white'
                  : 'border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100'
              }`}
            >
              {fw === 'ALL' ? 'All Frameworks' : fw}
            </button>
          ))}

          <select
            aria-label="Filter Controls by Status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700"
          >
            <option value="all">All Statuses</option>
            <option value="passing">Passing</option>
            <option value="failing">Failing</option>
            <option value="warning">Warning</option>
            <option value="waived">Waived</option>
            <option value="not_evaluated">Not Evaluated</option>
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {controls.length === 0 && (
            <button
              type="button"
              disabled={busy || !canWrite}
              onClick={handleSeedCatalog}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
            >
              Seed Baseline Catalog
            </button>
          )}
          <button
            type="button"
            disabled={busy || !canWrite}
            onClick={() => setShowCreate((prev) => !prev)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            New Control
          </button>
          <button
            type="button"
            disabled={busy || !canWrite}
            onClick={handleEvaluateAll}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Evaluate Controls
          </button>
        </div>
      </section>

      {showCreate && (
        <form
          onSubmit={handleCreateControl}
          className="grid gap-3 rounded-xl border border-indigo-200 bg-white p-5 shadow-sm sm:grid-cols-2"
        >
          <h3 className="sm:col-span-2 text-sm font-bold text-slate-900">
            Register Custom Compliance Control
          </h3>
          <input
            required
            placeholder="Control Code (e.g. SOC2-CC9.1)"
            value={controlCode}
            onChange={(e) => setControlCode(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <select
            aria-label="Custom Control Framework"
            value={framework}
            onChange={(e) => setFramework(e.target.value as FrameworkName)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          >
            <option value="SOC2">SOC 2</option>
            <option value="HIPAA">HIPAA</option>
            <option value="GDPR">GDPR</option>
          </select>
          <input
            required
            placeholder="Category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <select
            aria-label="Custom Control Severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input
            required
            placeholder="Control Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="sm:col-span-2 rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <input
            required
            placeholder="Mapped Rule IDs (comma-separated, e.g. CFG-001, ENC-001)"
            value={requiredRules}
            onChange={(e) => setRequiredRules(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <input
            required
            placeholder="Owner Email"
            value={ownerEmail}
            onChange={(e) => setOwnerEmail(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <textarea
            required
            rows={2}
            placeholder="Control Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="sm:col-span-2 rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <div className="sm:col-span-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
            >
              Save Control
            </button>
          </div>
        </form>
      )}

      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white p-6 text-center text-xs text-slate-500">
            No controls match the active filter.
          </div>
        ) : (
          filtered.map((ctrl) => (
            <article
              key={ctrl.id}
              className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-slate-900 px-2 py-0.5 font-mono text-[11px] font-semibold text-white">
                      {ctrl.control_code}
                    </span>
                    <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-semibold text-slate-700">
                      {ctrl.framework}
                    </span>
                    <StatusBadge status={ctrl.severity} />
                    <StatusBadge status={ctrl.status} />
                    <span className="text-xs font-bold text-indigo-700">
                      {ctrl.compliance_score.toFixed(1)}%
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">{ctrl.title}</h3>
                  <p className="text-xs text-slate-600">{ctrl.description}</p>
                  {ctrl.evidence_summary && (
                    <p className="text-xs font-medium text-slate-700">
                      Evidence: {ctrl.evidence_summary}
                    </p>
                  )}
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    {ctrl.required_rules_json.map((rule) => (
                      <span
                        key={rule}
                        className="rounded border border-indigo-100 bg-indigo-50 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-indigo-700"
                      >
                        {rule}
                      </span>
                    ))}
                  </div>
                </div>

                {canWrite && ctrl.status !== 'waived' && (
                  <button
                    type="button"
                    onClick={() =>
                      setWaiverControlId(waiverControlId === ctrl.id ? null : ctrl.id)
                    }
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
                  >
                    <ShieldQuestion className="h-3.5 w-3.5" />
                    Request Waiver
                  </button>
                )}
              </div>

              {waiverControlId === ctrl.id && (
                <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3">
                  <input
                    type="number"
                    min={1}
                    max={365}
                    aria-label="Waiver Days"
                    value={waiverDays}
                    onChange={(e) => setWaiverDays(Number(e.target.value) || 30)}
                    className="w-20 rounded border border-amber-300 bg-white px-2 py-1 text-xs"
                  />
                  <span className="text-xs text-amber-900">days</span>
                  <input
                    type="text"
                    placeholder="Business justification & compensating controls..."
                    value={waiverReason}
                    onChange={(e) => setWaiverReason(e.target.value)}
                    className="min-w-[220px] flex-1 rounded border border-amber-300 bg-white px-2.5 py-1 text-xs"
                  />
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleSubmitWaiver(ctrl.id)}
                    className="rounded bg-amber-700 px-3 py-1 text-xs font-semibold text-white hover:bg-amber-800"
                  >
                    Submit for HITL Approval
                  </button>
                </div>
              )}
            </article>
          ))
        )}
      </div>
    </div>
  );
}
