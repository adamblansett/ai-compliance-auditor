import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  CheckSquare,
  ClipboardCheck,
  Database,
  FileArchive,
  LayoutDashboard,
  Scale,
  ScanSearch,
} from 'lucide-react';
import {
  fetchApprovals,
  fetchAuditEvents,
  fetchBundles,
  fetchControls,
  fetchDsars,
  fetchHealth,
  fetchLegalHolds,
  fetchOverview,
  fetchRetentionExceptions,
  fetchRetentionPolicies,
  fetchScanFindings,
  fetchScanRuns,
  fetchScannerPresets,
  seedDemoData,
  verifyAuditChain,
} from './api/client';
import { ApprovalsView } from './components/ApprovalsView';
import { ControlsView } from './components/ControlsView';
import { EvidenceView } from './components/EvidenceView';
import { OverviewView } from './components/OverviewView';
import { PrivacyView } from './components/PrivacyView';
import { ScannersView } from './components/ScannersView';
import type {
  ActorContext,
  ActorRole,
  ApprovalRequestItem,
  AuditChainVerify,
  AuditEventItem,
  ControlItem,
  DsarRequestItem,
  EvidenceBundleItem,
  HealthStatus,
  LegalHoldItem,
  OverviewSummary,
  RetentionExceptionItem,
  RetentionPolicyItem,
  ScanFindingItem,
  ScanRunItem,
  ScannerPreset,
} from './types/compliance';

const NAV_TABS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'controls', label: 'Controls', icon: ClipboardCheck },
  { id: 'scanners', label: 'Scanners', icon: ScanSearch },
  { id: 'evidence', label: 'Evidence & Audit', icon: FileArchive },
  { id: 'privacy', label: 'Privacy & DSARs', icon: Scale },
  { id: 'approvals', label: 'Approvals', icon: CheckSquare },
] as const;

export default function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [offline, setOffline] = useState(false);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [actor, setActor] = useState<ActorContext>({
    email: 'officer@acme-compliance.local',
    role: 'compliance_officer',
  });
  const [banner, setBanner] = useState<{ text: string; isError: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  const [overview, setOverview] = useState<OverviewSummary | null>(null);
  const [controls, setControls] = useState<ControlItem[]>([]);
  const [presets, setPresets] = useState<ScannerPreset[]>([]);
  const [scanRuns, setScanRuns] = useState<ScanRunItem[]>([]);
  const [scanFindings, setScanFindings] = useState<ScanFindingItem[]>([]);
  const [bundles, setBundles] = useState<EvidenceBundleItem[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEventItem[]>([]);
  const [chainStatus, setChainStatus] = useState<AuditChainVerify | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequestItem[]>([]);
  const [dsars, setDsars] = useState<DsarRequestItem[]>([]);
  const [legalHolds, setLegalHolds] = useState<LegalHoldItem[]>([]);
  const [retentionPolicies, setRetentionPolicies] = useState<RetentionPolicyItem[]>([]);
  const [retentionExceptions, setRetentionExceptions] = useState<RetentionExceptionItem[]>([]);

  const notify = useCallback((text: string, isError = false) => {
    setBanner({ text, isError });
  }, []);

  const refreshWorkspace = useCallback(async () => {
    try {
      const [ov, ctrls, ps, runs, finds, bndls, evs, chain, apps, ds, holds, pols, excs] =
        await Promise.all([
          fetchOverview(actor),
          fetchControls(actor),
          fetchScannerPresets(actor),
          fetchScanRuns(actor),
          fetchScanFindings(actor),
          fetchBundles(actor),
          fetchAuditEvents(actor),
          verifyAuditChain(actor),
          fetchApprovals(actor),
          fetchDsars(actor),
          fetchLegalHolds(actor),
          fetchRetentionPolicies(actor),
          fetchRetentionExceptions(actor),
        ]);
      setOverview(ov);
      setControls(ctrls);
      setPresets(ps);
      setScanRuns(runs);
      setScanFindings(finds);
      setBundles(bndls);
      setAuditEvents(evs);
      setChainStatus(chain);
      setApprovals(apps);
      setDsars(ds);
      setLegalHolds(holds);
      setRetentionPolicies(pols);
      setRetentionExceptions(excs);
    } catch {
      // Keep UI resilient if secondary APIs are unavailable during offline preview
    }
  }, [actor]);

  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      try {
        const h = await fetchHealth();
        if (!cancelled) {
          setHealth(h);
          setOffline(false);
        }
        await refreshWorkspace();
      } catch {
        if (!cancelled) {
          setOffline(true);
        }
      }
    }
    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, [refreshWorkspace]);

  async function handleLoadDemo(reset = false) {
    setBusy(true);
    try {
      const res = await seedDemoData(actor, reset);
      notify(res.message);
      await refreshWorkspace();
    } catch (err) {
      notify(err instanceof Error ? err.message : 'Demo seed failed', true);
    } finally {
      setBusy(false);
    }
  }

  function handleRoleChange(role: ActorRole) {
    const emailMap: Record<ActorRole, string> = {
      compliance_officer: 'officer@acme-compliance.local',
      auditor: 'auditor@acme-compliance.local',
      viewer: 'viewer@acme-compliance.local',
      admin: 'admin@acme-compliance.local',
    };
    const email = emailMap[role];
    setActor({ email, role });
    notify(`Switched active actor to ${email} (${role}).`);
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
              SOC 2 · HIPAA · GDPR Governance Workspace
            </p>
            <h1 className="mt-0.5 text-xl font-bold tracking-tight text-slate-900">
              AI Compliance &amp; Regulatory Auditor
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <label className="flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700">
              <span>Role:</span>
              <select
                aria-label="Actor Role"
                value={actor.role}
                onChange={(e) => handleRoleChange(e.target.value as ActorRole)}
                className="bg-transparent font-semibold text-indigo-700 focus:outline-none"
              >
                <option value="compliance_officer">Compliance Officer</option>
                <option value="auditor">Auditor</option>
                <option value="viewer">Viewer</option>
              </select>
            </label>

            <button
              type="button"
              onClick={() => handleLoadDemo(true)}
              disabled={busy || offline || actor.role === 'viewer'}
              className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
            >
              <Database className="h-3.5 w-3.5" />
              {busy ? 'Loading...' : 'Reset Demo Data'}
            </button>

            <div className="flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3.5 py-1.5 text-xs font-medium">
              <Activity
                className={`h-3.5 w-3.5 ${
                  health?.status === 'ok'
                    ? 'text-emerald-600'
                    : offline
                      ? 'text-amber-600'
                      : 'text-slate-400'
                }`}
              />
              <span>
                {health?.status === 'ok'
                  ? `API Healthy (${health.llm_provider})`
                  : offline
                    ? 'Offline Starter Preview'
                    : 'Checking API...'}
              </span>
            </div>
          </div>
        </div>

        <nav
          aria-label="Compliance Auditor Modules"
          className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-6 pb-2"
        >
          {NAV_TABS.map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition ${
                  active
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </header>

      <main className="mx-auto max-w-6xl space-y-5 px-6 py-6">
        {banner && (
          <div
            role="status"
            className={`flex items-center justify-between rounded-xl border px-4 py-2.5 text-xs font-medium ${
              banner.isError
                ? 'border-rose-200 bg-rose-50 text-rose-800'
                : 'border-emerald-200 bg-emerald-50 text-emerald-800'
            }`}
          >
            <span>{banner.text}</span>
            <button
              type="button"
              onClick={() => setBanner(null)}
              className="ml-4 text-xs underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {activeTab === 'overview' && (
          <OverviewView
            overview={overview}
            approvals={approvals}
            onNavigate={setActiveTab}
            onLoadDemo={() => handleLoadDemo(false)}
            busy={busy}
          />
        )}

        {activeTab === 'controls' && (
          <ControlsView
            actor={actor}
            controls={controls}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'scanners' && (
          <ScannersView
            actor={actor}
            presets={presets}
            runs={scanRuns}
            findings={scanFindings}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'evidence' && (
          <EvidenceView
            actor={actor}
            bundles={bundles}
            auditEvents={auditEvents}
            chainStatus={chainStatus}
            onChainVerified={setChainStatus}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'privacy' && (
          <PrivacyView
            actor={actor}
            dsars={dsars}
            legalHolds={legalHolds}
            retentionPolicies={retentionPolicies}
            retentionExceptions={retentionExceptions}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}

        {activeTab === 'approvals' && (
          <ApprovalsView
            actor={actor}
            approvals={approvals}
            onRefresh={refreshWorkspace}
            onNotify={notify}
          />
        )}
      </main>
    </div>
  );
}
