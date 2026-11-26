import { FormEvent, useState } from 'react';
import { CalendarClock, FileUp, FolderGit2, Globe, Play, Search } from 'lucide-react';
import {
  createScheduledScan,
  probeLiveUrl,
  runInlineScan,
  runScheduledScan,
  scanRepository,
  uploadScanArtifact,
} from '../api/client';
import { StatusBadge } from './StatusBadge';
import type {
  ActorContext,
  ScanFindingItem,
  ScanRunItem,
  ScannerPreset,
  ScheduledScanItem,
  TargetType,
} from '../types/compliance';

interface ScannersViewProps {
  actor: ActorContext;
  presets: ScannerPreset[];
  runs: ScanRunItem[];
  findings: ScanFindingItem[];
  schedules: ScheduledScanItem[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

type ScanTabMode = 'single' | 'repo' | 'url' | 'schedules';

export function ScannersView({
  actor,
  presets,
  runs,
  findings,
  schedules,
  onRefresh,
  onNotify,
}: ScannersViewProps) {
  const [scanMode, setScanMode] = useState<ScanTabMode>('single');

  const [targetName, setTargetName] = useState('custom-service-config');
  const [targetType, setTargetType] = useState<TargetType>('config');
  const [filename, setFilename] = useState('service.env');
  const [content, setContent] = useState(
    'APP_ENV=production\nDEBUG=false\nCORS_ORIGINS=https://app.example.com\nSSL_VERIFY=true\n',
  );
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [repoTargetName, setRepoTargetName] = useState('service-iac-repo');
  const [repoPath, setRepoPath] = useState('');
  const [repoSampleFiles, setRepoSampleFiles] = useState(
    JSON.stringify(
      [
        {
          path: 'deploy/prod.env',
          content: 'APP_ENV=production\nDEBUG=false\nCORS_ORIGINS=https://app.example.com\n',
        },
        {
          path: 'infra/nginx.conf',
          content: 'ssl_protocols TLSv1.3;\nencryption_at_rest=true\nkey_rotation=true\n',
        },
      ],
      null,
      2,
    ),
  );

  const [urlTargetName, setUrlTargetName] = useState('public-api-gateway');
  const [probeUrl, setProbeUrl] = useState('https://example.com');

  const [schedName, setSchedName] = useState('Hourly Drift Check');
  const [schedMode, setSchedMode] = useState<'preset' | 'repo_path' | 'url_probe'>('preset');
  const [schedRef, setSchedRef] = useState('failing-staging-config');
  const [schedInterval, setSchedInterval] = useState(60);

  const [busy, setBusy] = useState(false);
  const [domainFilter, setDomainFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const canWrite = actor.role !== 'viewer';

  function applyPreset(preset: ScannerPreset) {
    setScanMode('single');
    setTargetName(preset.target_name);
    setTargetType(preset.target_type);
    setFilename(preset.artifact_filename);
    setContent(preset.content);
    setSelectedFile(null);
    onNotify(`Loaded preset: ${preset.label}`);
  }

  async function handleRunScan(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = selectedFile
        ? await uploadScanArtifact(actor, selectedFile, targetName, targetType, true)
        : await runInlineScan(actor, {
            target_name: targetName,
            target_type: targetType,
            artifact_filename: filename,
            content,
            auto_evaluate_controls: true,
          });
      onNotify(
        `Scan '${res.target_name}' completed (${res.status}): ${res.passed_checks} pass, ${res.failed_checks} fail, ${res.warning_checks} warn.`,
      );
      setSelectedFile(null);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Scan execution failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleRepoScan(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const parsedFiles = repoPath.trim()
        ? []
        : (JSON.parse(repoSampleFiles) as Array<{ path: string; content: string }>);
      const res = await scanRepository(actor, {
        target_name: repoTargetName,
        repo_path: repoPath.trim() || undefined,
        files: parsedFiles,
        auto_evaluate_controls: true,
      });
      onNotify(
        `Repository scan '${res.target_name}' completed (${res.status}): ${res.total_checks} check(s).`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Repository scan failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleProbeUrl(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await probeLiveUrl(actor, {
        target_name: urlTargetName,
        url: probeUrl,
        auto_evaluate_controls: true,
      });
      onNotify(`URL probe '${res.target_name}' completed (${res.status}).`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Live URL probe failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateSchedule(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const sched = await createScheduledScan(actor, {
        name: schedName,
        scan_mode: schedMode,
        target_ref: schedRef,
        target_type: 'full_suite',
        interval_minutes: schedInterval,
      });
      onNotify(`Created scheduled scan '${sched.name}' every ${sched.interval_minutes}m.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Schedule creation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleRunScheduleNow(scheduleId: string) {
    setBusy(true);
    try {
      const res = await runScheduledScan(actor, scheduleId);
      onNotify(`Executed scheduled scan '${res.target_name}' (${res.status}).`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Scheduled run failed', true);
    } finally {
      setBusy(false);
    }
  }

  const filteredFindings = findings.filter((f) => {
    if (domainFilter !== 'all' && f.domain !== domainFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-900">
              Policy, Repo, Endpoint &amp; Scheduled Scanners
            </h2>
            <p className="mt-1 text-xs text-slate-600">
              Scan single configs/SOPs, multi-file repositories, live HTTPS endpoints, or recurring
              drift schedules. Findings auto-evaluate mapped SOC 2, HIPAA, and GDPR controls.
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(
              [
                { id: 'single', label: 'Single Artifact', icon: Play },
                { id: 'repo', label: 'Multi-File / Repo', icon: FolderGit2 },
                { id: 'url', label: 'Live URL / TLS', icon: Globe },
                { id: 'schedules', label: `Schedules (${schedules.length})`, icon: CalendarClock },
              ] as const
            ).map((m) => {
              const Icon = m.icon;
              return (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setScanMode(m.id)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold ${
                    scanMode === m.id
                      ? 'bg-indigo-600 text-white'
                      : 'border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {m.label}
                </button>
              );
            })}
          </div>
        </div>

        {scanMode === 'single' && (
          <>
            {presets.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  Presets:
                </span>
                {presets.map((p) => (
                  <button
                    key={p.preset_id}
                    type="button"
                    onClick={() => applyPreset(p)}
                    className="rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            )}

            <form onSubmit={handleRunScan} className="mt-4 space-y-3">
              <div className="grid gap-3 sm:grid-cols-3">
                <input
                  required
                  aria-label="Scan Target Name"
                  placeholder="Target Name"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
                />
                <select
                  aria-label="Scanner Domain"
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value as TargetType)}
                  className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
                >
                  <option value="config">Config Hygiene (CFG-*)</option>
                  <option value="encryption">Encryption &amp; TLS (ENC-*)</option>
                  <option value="logging">Logging &amp; PHI Scrubbing (LOG-*)</option>
                  <option value="rbac">IAM &amp; RBAC Policy (RBAC-*)</option>
                  <option value="sop">Security &amp; Privacy SOP (SOP-*)</option>
                  <option value="full_suite">Full 5-Domain Suite</option>
                </select>
                <input
                  required
                  aria-label="Artifact Filename"
                  placeholder="Filename"
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
                />
              </div>

              <textarea
                rows={5}
                aria-label="Artifact Content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Paste config, IAM JSON, log lines, or SOP markdown..."
                className="w-full rounded-lg border border-slate-300 p-3 font-mono text-xs"
              />

              <div className="flex flex-wrap items-center justify-between gap-3">
                <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100">
                  <FileUp className="h-3.5 w-3.5" />
                  <span>{selectedFile ? `Selected: ${selectedFile.name}` : 'Or Upload File'}</span>
                  <input
                    type="file"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0] || null;
                      setSelectedFile(file);
                      if (file) setFilename(file.name);
                    }}
                  />
                </label>

                <button
                  type="submit"
                  disabled={busy || !canWrite}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {busy ? 'Scanning...' : 'Run Compliance Scan'}
                </button>
              </div>
            </form>
          </>
        )}

        {scanMode === 'repo' && (
          <form onSubmit={handleRepoScan} className="mt-4 space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <input
                required
                aria-label="Repository Target Name"
                placeholder="Target Name"
                value={repoTargetName}
                onChange={(e) => setRepoTargetName(e.target.value)}
                className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
              />
              <input
                aria-label="Local Repository Path (Optional)"
                placeholder="Optional local directory path (leave empty to scan JSON files below)"
                value={repoPath}
                onChange={(e) => setRepoPath(e.target.value)}
                className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
              />
            </div>
            <textarea
              rows={5}
              aria-label="Repository Files JSON"
              value={repoSampleFiles}
              onChange={(e) => setRepoSampleFiles(e.target.value)}
              className="w-full rounded-lg border border-slate-300 p-2.5 font-mono text-xs"
            />
            <button
              type="submit"
              disabled={busy || !canWrite}
              className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              <FolderGit2 className="h-3.5 w-3.5" />
              {busy ? 'Scanning Repo...' : 'Scan Repository Bundle'}
            </button>
          </form>
        )}

        {scanMode === 'url' && (
          <form onSubmit={handleProbeUrl} className="mt-4 flex flex-wrap gap-2.5">
            <input
              required
              aria-label="URL Probe Target Name"
              placeholder="Endpoint Name"
              value={urlTargetName}
              onChange={(e) => setUrlTargetName(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
            />
            <input
              required
              type="url"
              aria-label="Live Endpoint URL"
              placeholder="https://example.com"
              value={probeUrl}
              onChange={(e) => setProbeUrl(e.target.value)}
              className="min-w-[240px] flex-1 rounded-lg border border-slate-300 px-3 py-2 text-xs"
            />
            <button
              type="submit"
              disabled={busy || !canWrite}
              className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              <Globe className="h-3.5 w-3.5" />
              {busy ? 'Probing...' : 'Probe TLS & Headers'}
            </button>
          </form>
        )}

        {scanMode === 'schedules' && (
          <div className="mt-4 space-y-4">
            <form onSubmit={handleCreateSchedule} className="grid gap-2.5 sm:grid-cols-5">
              <input
                required
                placeholder="Schedule Name"
                value={schedName}
                onChange={(e) => setSchedName(e.target.value)}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
              />
              <select
                aria-label="Schedule Scan Mode"
                value={schedMode}
                onChange={(e) =>
                  setSchedMode(e.target.value as 'preset' | 'repo_path' | 'url_probe')
                }
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
              >
                <option value="preset">Preset</option>
                <option value="repo_path">Repo Path</option>
                <option value="url_probe">URL Probe</option>
              </select>
              <input
                required
                placeholder="Target (preset ID, path, or URL)"
                value={schedRef}
                onChange={(e) => setSchedRef(e.target.value)}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
              />
              <input
                type="number"
                min={1}
                aria-label="Interval Minutes"
                value={schedInterval}
                onChange={(e) => setSchedInterval(Number(e.target.value) || 60)}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
              />
              <button
                type="submit"
                disabled={busy || !canWrite}
                className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
              >
                Add Schedule
              </button>
            </form>

            <div className="space-y-2">
              {schedules.map((s) => (
                <div
                  key={s.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs"
                >
                  <div>
                    <span className="font-bold text-slate-900">{s.name}</span>
                    <span className="ml-2 font-mono text-[11px] text-slate-600">
                      {s.scan_mode}: {s.target_ref} (every {s.interval_minutes}m)
                    </span>
                  </div>
                  <button
                    type="button"
                    disabled={busy || !canWrite}
                    onClick={() => handleRunScheduleNow(s.id)}
                    className="rounded border border-indigo-200 bg-indigo-50 px-2.5 py-1 font-semibold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
                  >
                    Run Now
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="text-sm font-bold text-slate-900">
          Executed Scan Runs ({runs.length})
        </h3>
        {runs.length === 0 ? (
          <p className="mt-2 text-xs text-slate-500">No scans executed yet.</p>
        ) : (
          <div className="mt-3 space-y-2.5">
            {runs.slice(0, 8).map((run) => (
              <div
                key={run.id}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold text-slate-900">{run.target_name}</span>
                    <span className="rounded bg-white px-2 py-0.5 font-mono text-[11px] text-slate-600">
                      {run.target_type}
                    </span>
                    <StatusBadge status={run.status} />
                  </div>
                  <div className="flex items-center gap-3 text-slate-600">
                    <span>Risk: {run.risk_score}</span>
                    <span className="font-mono text-[11px]">
                      SHA-256: {run.artifact_sha256.slice(0, 12)}...
                    </span>
                  </div>
                </div>
                <p className="mt-1.5 text-slate-600">{run.ai_summary}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-indigo-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Scanner Findings ({filteredFindings.length})
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            <select
              aria-label="Filter Findings by Domain"
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs"
            >
              <option value="all">All Domains</option>
              <option value="config">Config</option>
              <option value="encryption">Encryption</option>
              <option value="logging">Logging</option>
              <option value="rbac">RBAC</option>
              <option value="sop">SOP</option>
            </select>
            <select
              aria-label="Filter Findings by Status"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs"
            >
              <option value="all">All Outcomes</option>
              <option value="fail">Fail</option>
              <option value="warning">Warning</option>
              <option value="pass">Pass</option>
            </select>
          </div>
        </div>

        <div className="mt-3 space-y-2.5">
          {filteredFindings.slice(0, 25).map((f) => (
            <div key={f.id} className="rounded-lg border border-slate-200 p-3 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-white">
                  {f.rule_id}
                </span>
                <StatusBadge status={f.status} />
                <StatusBadge status={f.severity} />
                <span className="font-semibold text-slate-900">{f.title}</span>
              </div>
              <p className="mt-1 text-slate-600">{f.detail}</p>
              {f.evidence_snippet && (
                <pre className="mt-1.5 overflow-x-auto rounded bg-slate-900 p-2 font-mono text-[11px] text-emerald-300">
                  {f.evidence_snippet}
                </pre>
              )}
              {f.mapped_controls_json.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] text-slate-500">Controls:</span>
                  {f.mapped_controls_json.map((code) => (
                    <span
                      key={code}
                      className="rounded border border-indigo-100 bg-indigo-50 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-indigo-700"
                    >
                      {code}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
