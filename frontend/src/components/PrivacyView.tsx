import { FormEvent, useState } from 'react';
import { Lock, RefreshCw, Scale, UserCheck } from 'lucide-react';
import {
  createDsar,
  createLegalHold,
  createRetentionPolicy,
  prepareDsarFulfillment,
  releaseLegalHold,
  requestRetentionException,
  verifyRetentionPolicies,
} from '../api/client';
import { StatusBadge } from './StatusBadge';
import type {
  ActorContext,
  DsarRequestItem,
  DsarType,
  FrameworkName,
  LegalHoldItem,
  RegulationType,
  RetentionExceptionItem,
  RetentionPolicyItem,
} from '../types/compliance';

interface PrivacyViewProps {
  actor: ActorContext;
  dsars: DsarRequestItem[];
  legalHolds: LegalHoldItem[];
  retentionPolicies: RetentionPolicyItem[];
  retentionExceptions: RetentionExceptionItem[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

export function PrivacyView({
  actor,
  dsars,
  legalHolds,
  retentionPolicies,
  retentionExceptions,
  onRefresh,
  onNotify,
}: PrivacyViewProps) {
  const [busy, setBusy] = useState(false);

  const [dsarType, setDsarType] = useState<DsarType>('erasure');
  const [regulation, setRegulation] = useState<RegulationType>('GDPR');
  const [subjectEmail, setSubjectEmail] = useState('');
  const [systemsInput, setSystemsInput] = useState('crm_postgres, billing_ledger');
  const [dsarNotes, setDsarNotes] = useState('');

  const [holdTitle, setHoldTitle] = useState('');
  const [matterRef, setMatterRef] = useState('');
  const [custodiansInput, setCustodiansInput] = useState('');
  const [holdSystemsInput, setHoldSystemsInput] = useState('billing_ledger, crm_postgres');
  const [holdReason, setHoldReason] = useState('');
  const [releaseHoldId, setReleaseHoldId] = useState<string | null>(null);
  const [releaseReason, setReleaseReason] = useState('');

  const [policyCode, setPolicyCode] = useState('');
  const [dataCategory, setDataCategory] = useState('');
  const [retFramework, setRetFramework] = useState<FrameworkName>('GDPR');
  const [systemName, setSystemName] = useState('');
  const [retentionDays, setRetentionDays] = useState(90);
  const [oldestDays, setOldestDays] = useState(45);

  const [excPolicyId, setExcPolicyId] = useState<string | null>(null);
  const [excDays, setExcDays] = useState(180);
  const [excExpiresAt, setExcExpiresAt] = useState('2027-06-30');
  const [excJustification, setExcJustification] = useState('');

  const canWrite = actor.role !== 'viewer';
  const isOfficer = actor.role === 'compliance_officer' || actor.role === 'admin';

  async function handleCreateDsar(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const systems = systemsInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const created = await createDsar(actor, {
        request_type: dsarType,
        regulation,
        subject_email: subjectEmail,
        data_systems: systems,
        notes: dsarNotes,
      });
      onNotify(
        `Created ${created.reference_code} (${created.status}) — due ${created.due_date}.`,
        created.legal_hold_blocked,
      );
      setSubjectEmail('');
      setDsarNotes('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'DSAR creation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handlePrepareDsar(dsarId: string) {
    setBusy(true);
    try {
      const updated = await prepareDsarFulfillment(actor, dsarId);
      onNotify(
        `Prepared ${updated.reference_code} export package and queued HITL fulfillment approval.`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'DSAR preparation blocked', true);
      await onRefresh();
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateHold(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const created = await createLegalHold(actor, {
        title: holdTitle,
        matter_reference: matterRef,
        custodian_scope: custodiansInput
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        systems_scope: holdSystemsInput
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        reason: holdReason,
      });
      onNotify(`Placed active legal hold ${created.hold_code}.`);
      setHoldTitle('');
      setMatterRef('');
      setCustodiansInput('');
      setHoldReason('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Legal hold placement failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleReleaseHold(holdId: string) {
    if (!releaseReason.trim()) {
      onNotify('Provide a release reason.', true);
      return;
    }
    setBusy(true);
    try {
      const released = await releaseLegalHold(actor, holdId, releaseReason);
      onNotify(`Released legal hold ${released.hold_code} and re-evaluated affected DSARs.`);
      setReleaseHoldId(null);
      setReleaseReason('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Release hold failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleCreatePolicy(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const created = await createRetentionPolicy(actor, {
        policy_code: policyCode,
        data_category: dataCategory,
        framework: retFramework,
        system_name: systemName,
        retention_days: retentionDays,
        actual_oldest_record_days: oldestDays,
        purge_mechanism: 'Automated scheduled purge job',
        encryption_at_rest: true,
      });
      onNotify(`Created retention policy ${created.policy_code} (${created.status}).`);
      setPolicyCode('');
      setDataCategory('');
      setSystemName('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Retention policy creation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyRetention() {
    setBusy(true);
    try {
      const policies = await verifyRetentionPolicies(actor);
      const violations = policies.filter((p) => p.status === 'violation_over_retained').length;
      onNotify(`Verified ${policies.length} retention policy(ies); ${violations} violation(s).`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Retention verification failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleSubmitException(policyId: string) {
    if (!excJustification.trim()) {
      onNotify('Provide a justification for the retention exception.', true);
      return;
    }
    setBusy(true);
    try {
      await requestRetentionException(actor, policyId, {
        requested_retention_days: excDays,
        justification: excJustification,
        expires_at: excExpiresAt,
      });
      onNotify('Submitted retention exception request for HITL officer approval.');
      setExcPolicyId(null);
      setExcJustification('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Exception request failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <UserCheck className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-bold text-slate-900">
            DSAR Fulfillment Tracker ({dsars.length})
          </h2>
        </div>

        <form onSubmit={handleCreateDsar} className="mt-3 grid gap-2.5 sm:grid-cols-5">
          <select
            aria-label="DSAR Request Type"
            value={dsarType}
            onChange={(e) => setDsarType(e.target.value as DsarType)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          >
            <option value="access">Access</option>
            <option value="erasure">Erasure</option>
            <option value="portability">Portability</option>
            <option value="rectification">Rectification</option>
            <option value="restriction">Restriction</option>
          </select>
          <select
            aria-label="DSAR Regulation"
            value={regulation}
            onChange={(e) => setRegulation(e.target.value as RegulationType)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          >
            <option value="GDPR">GDPR</option>
            <option value="CCPA">CCPA</option>
            <option value="HIPAA">HIPAA</option>
          </select>
          <input
            required
            type="email"
            placeholder="Subject Email"
            value={subjectEmail}
            onChange={(e) => setSubjectEmail(e.target.value)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
          <input
            placeholder="Data systems (comma-separated)"
            value={systemsInput}
            onChange={(e) => setSystemsInput(e.target.value)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
          <button
            type="submit"
            disabled={busy || !canWrite}
            className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            Log DSAR
          </button>
          <input
            placeholder="Intake notes (optional)"
            value={dsarNotes}
            onChange={(e) => setDsarNotes(e.target.value)}
            className="sm:col-span-5 rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
        </form>

        <div className="mt-4 space-y-2.5">
          {dsars.map((d) => (
            <div
              key={d.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-bold text-slate-900">{d.reference_code}</span>
                  <span className="rounded bg-white px-2 py-0.5 text-[11px] font-semibold uppercase text-slate-700">
                    {d.regulation} · {d.request_type}
                  </span>
                  <StatusBadge status={d.status} />
                  <span className="text-slate-500">Due: {d.due_date}</span>
                </div>
                <p className="text-slate-600">
                  Subject: {d.subject_email} · Systems: {d.data_systems_json.join(', ')}
                </p>
                {d.blocking_hold_ids_json.length > 0 && (
                  <p className="font-semibold text-rose-700">
                    Blocked by Legal Hold(s): {d.blocking_hold_ids_json.join(', ')}
                  </p>
                )}
              </div>

              {canWrite && d.status !== 'completed' && d.status !== 'pending_approval' && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => handlePrepareDsar(d.id)}
                  className="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-1.5 font-semibold text-indigo-700 hover:bg-indigo-100"
                >
                  Prepare Fulfillment
                </button>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-amber-600" />
          <h3 className="text-sm font-bold text-slate-900">
            Legal Holds ({legalHolds.length})
          </h3>
        </div>

        <form onSubmit={handleCreateHold} className="mt-3 grid gap-2.5 sm:grid-cols-2">
          <input
            required
            placeholder="Legal Hold Title"
            value={holdTitle}
            onChange={(e) => setHoldTitle(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <input
            required
            placeholder="Matter Reference (e.g. MATTER-2026-99)"
            value={matterRef}
            onChange={(e) => setMatterRef(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <input
            placeholder="Custodian emails or @domain (comma-separated)"
            value={custodiansInput}
            onChange={(e) => setCustodiansInput(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <input
            placeholder="Scoped Systems (comma-separated)"
            value={holdSystemsInput}
            onChange={(e) => setHoldSystemsInput(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <input
            required
            placeholder="Preservation reason..."
            value={holdReason}
            onChange={(e) => setHoldReason(e.target.value)}
            className="sm:col-span-2 rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <div className="sm:col-span-2 flex justify-end">
            <button
              type="submit"
              disabled={busy || !isOfficer}
              title={isOfficer ? '' : 'Compliance Officer or Admin role required'}
              className="rounded-lg bg-amber-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-amber-700 disabled:opacity-50"
            >
              Place Legal Hold
            </button>
          </div>
        </form>

        <div className="mt-4 space-y-2.5">
          {legalHolds.map((h) => (
            <div key={h.id} className="rounded-lg border border-slate-200 p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-slate-900">{h.hold_code}</span>
                  <StatusBadge status={h.status} />
                  <span className="font-semibold text-slate-800">{h.title}</span>
                </div>
                {isOfficer && h.status === 'active' && (
                  <button
                    type="button"
                    onClick={() => setReleaseHoldId(releaseHoldId === h.id ? null : h.id)}
                    className="rounded border border-slate-300 bg-white px-2.5 py-1 font-semibold text-slate-700 hover:bg-slate-50"
                  >
                    Release Hold
                  </button>
                )}
              </div>
              <p className="mt-1 text-slate-600">
                Matter: {h.matter_reference} · Custodians: {h.custodian_scope_json.join(', ') || '*'}{' '}
                · Systems: {h.systems_scope_json.join(', ')}
              </p>

              {releaseHoldId === h.id && (
                <div className="mt-2 flex flex-wrap gap-2">
                  <input
                    type="text"
                    placeholder="Release justification..."
                    value={releaseReason}
                    onChange={(e) => setReleaseReason(e.target.value)}
                    className="flex-1 rounded border border-slate-300 px-2.5 py-1 text-xs"
                  />
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleReleaseHold(h.id)}
                    className="rounded bg-slate-900 px-3 py-1 text-xs font-semibold text-white"
                  >
                    Confirm Release
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Scale className="h-4 w-4 text-indigo-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Data Retention Policies &amp; Exceptions ({retentionPolicies.length})
            </h3>
          </div>
          <button
            type="button"
            disabled={busy || !canWrite}
            onClick={handleVerifyRetention}
            className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Verify All Policies
          </button>
        </div>

        <form onSubmit={handleCreatePolicy} className="mt-3 grid gap-2 sm:grid-cols-6">
          <input
            required
            placeholder="Code (RET-010)"
            value={policyCode}
            onChange={(e) => setPolicyCode(e.target.value)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
          <input
            required
            placeholder="Data Category"
            value={dataCategory}
            onChange={(e) => setDataCategory(e.target.value)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
          <select
            aria-label="Retention Framework"
            value={retFramework}
            onChange={(e) => setRetFramework(e.target.value as FrameworkName)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          >
            <option value="GDPR">GDPR</option>
            <option value="SOC2">SOC 2</option>
            <option value="HIPAA">HIPAA</option>
          </select>
          <input
            required
            placeholder="System Name"
            value={systemName}
            onChange={(e) => setSystemName(e.target.value)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
          <input
            type="number"
            min={1}
            aria-label="Max Retention Days"
            value={retentionDays}
            onChange={(e) => setRetentionDays(Number(e.target.value) || 90)}
            className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs"
          />
          <div className="flex gap-1.5">
            <input
              type="number"
              min={0}
              aria-label="Oldest Record Age Days"
              value={oldestDays}
              onChange={(e) => setOldestDays(Number(e.target.value) || 0)}
              className="w-20 rounded-lg border border-slate-300 px-2 py-1.5 text-xs"
            />
            <button
              type="submit"
              disabled={busy || !canWrite}
              className="flex-1 rounded-lg bg-indigo-600 px-2.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              Add
            </button>
          </div>
        </form>

        <div className="mt-4 space-y-2.5">
          {retentionPolicies.map((pol) => (
            <div key={pol.id} className="rounded-lg border border-slate-200 p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-bold text-slate-900">{pol.policy_code}</span>
                  <span className="font-semibold text-slate-800">{pol.data_category}</span>
                  <StatusBadge status={pol.status} />
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-slate-600">
                    Limit: {pol.retention_days}d · Oldest: {pol.actual_oldest_record_days}d (
                    {pol.system_name})
                  </span>
                  {canWrite && (
                    <button
                      type="button"
                      onClick={() => setExcPolicyId(excPolicyId === pol.id ? null : pol.id)}
                      className="rounded border border-slate-300 bg-white px-2 py-1 font-semibold text-slate-700 hover:bg-slate-50"
                    >
                      Request Exception
                    </button>
                  )}
                </div>
              </div>

              {excPolicyId === pol.id && (
                <div className="mt-2.5 flex flex-wrap items-center gap-2 rounded border border-amber-200 bg-amber-50 p-2.5">
                  <input
                    type="number"
                    min={1}
                    aria-label="Requested Retention Days"
                    value={excDays}
                    onChange={(e) => setExcDays(Number(e.target.value) || 180)}
                    className="w-20 rounded border border-amber-300 bg-white px-2 py-1 text-xs"
                  />
                  <input
                    type="date"
                    aria-label="Exception Expiration Date"
                    value={excExpiresAt}
                    onChange={(e) => setExcExpiresAt(e.target.value)}
                    className="rounded border border-amber-300 bg-white px-2 py-1 text-xs"
                  />
                  <input
                    type="text"
                    placeholder="Business/regulatory justification..."
                    value={excJustification}
                    onChange={(e) => setExcJustification(e.target.value)}
                    className="min-w-[200px] flex-1 rounded border border-amber-300 bg-white px-2 py-1 text-xs"
                  />
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleSubmitException(pol.id)}
                    className="rounded bg-amber-700 px-3 py-1 text-xs font-semibold text-white"
                  >
                    Queue HITL Exception
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>

        {retentionExceptions.length > 0 && (
          <div className="mt-4 border-t border-slate-200 pt-3">
            <h4 className="text-xs font-bold uppercase tracking-wide text-slate-500">
              Retention Exceptions ({retentionExceptions.length})
            </h4>
            <div className="mt-2 space-y-1.5">
              {retentionExceptions.map((ex) => (
                <div
                  key={ex.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded bg-slate-50 px-3 py-2 text-xs"
                >
                  <span>
                    Extend to {ex.requested_retention_days}d (expires {ex.expires_at}) —{' '}
                    {ex.justification}
                  </span>
                  <StatusBadge status={ex.status} />
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
