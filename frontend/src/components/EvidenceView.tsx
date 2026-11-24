import { FormEvent, useState } from 'react';
import {
  CheckCircle2,
  Download,
  FileArchive,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  compileBundle,
  exportBundle,
  redactPiiText,
  verifyAuditChain,
  verifyBundleById,
  verifyBundlePayload,
} from '../api/client';
import { StatusBadge } from './StatusBadge';
import type {
  ActorContext,
  AuditChainVerify,
  AuditEventItem,
  BundleVerifyResult,
  EvidenceBundleItem,
  FrameworkName,
  PiiRedactResult,
} from '../types/compliance';

interface EvidenceViewProps {
  actor: ActorContext;
  bundles: EvidenceBundleItem[];
  auditEvents: AuditEventItem[];
  chainStatus: AuditChainVerify | null;
  onChainVerified: (res: AuditChainVerify) => void;
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

export function EvidenceView({
  actor,
  bundles,
  auditEvents,
  chainStatus,
  onChainVerified,
  onRefresh,
  onNotify,
}: EvidenceViewProps) {
  const [bundleName, setBundleName] = useState('Q4 2026 External Audit Package');
  const [frameworks, setFrameworks] = useState<FrameworkName[]>(['SOC2', 'HIPAA', 'GDPR']);
  const [busy, setBusy] = useState(false);

  const [bundleVerifyResult, setBundleVerifyResult] = useState<BundleVerifyResult | null>(null);
  const [verifierJson, setVerifierJson] = useState('');
  const [expectedManifestSha, setExpectedManifestSha] = useState('');

  const [piiInput, setPiiInput] = useState(
    'Patient email=alice@clinic.org ssn=123-45-6789 mrn=MRN-88210 dob=1982-09-14 key=sk-live1234567890abcdef',
  );
  const [piiResult, setPiiResult] = useState<PiiRedactResult | null>(null);

  const canWrite = actor.role !== 'viewer';

  function toggleFramework(fw: FrameworkName) {
    setFrameworks((prev) =>
      prev.includes(fw) ? prev.filter((item) => item !== fw) : [...prev, fw],
    );
  }

  async function handleCompileBundle(e: FormEvent) {
    e.preventDefault();
    if (frameworks.length === 0) {
      onNotify('Select at least one framework to compile.', true);
      return;
    }
    setBusy(true);
    try {
      const compiled = await compileBundle(actor, {
        bundle_name: bundleName,
        frameworks,
      });
      onNotify(
        `Compiled '${compiled.bundle_name}' (${compiled.item_count} chained items) and queued HITL release approval.`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Bundle compilation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyBundle(bundleId: string) {
    setBusy(true);
    try {
      const res = await verifyBundleById(actor, bundleId);
      setBundleVerifyResult(res);
      onNotify(res.message, !res.valid);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Bundle verification failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleLoadBundleIntoVerifier(bundleId: string) {
    setBusy(true);
    try {
      const exported = await exportBundle(actor, bundleId);
      setVerifierJson(JSON.stringify(exported.manifest, null, 2));
      setExpectedManifestSha(exported.manifest_sha256);
      setBundleVerifyResult(null);
      onNotify(`Loaded manifest for '${exported.bundle_name}' into independent verifier.`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Export failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleDownloadBundle(bundleId: string) {
    try {
      const exported = await exportBundle(actor, bundleId);
      const blob = new Blob([JSON.stringify(exported, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${exported.bundle_name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      onNotify(`Exported '${exported.bundle_name}' JSON package.`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Download failed', true);
    }
  }

  function handleSimulateTamper() {
    if (!verifierJson.trim()) {
      onNotify('Load a bundle into the verifier first.', true);
      return;
    }
    try {
      const parsed = JSON.parse(verifierJson) as {
        evidence_chain?: Array<{ payload?: Record<string, unknown> }>;
      };
      const firstItem = parsed.evidence_chain?.[0];
      if (firstItem && firstItem.payload) {
        firstItem.payload.tampered_note = 'TAMPERED_BY_VERIFIER_DEMO';
        setVerifierJson(JSON.stringify(parsed, null, 2));
        onNotify('Modified 1 payload field inside manifest without updating hashes.');
      }
    } catch {
      onNotify('Manifest JSON is invalid; cannot simulate tamper.', true);
    }
  }

  async function handleVerifyPayload() {
    if (!verifierJson.trim()) {
      onNotify('Paste or load a bundle manifest JSON first.', true);
      return;
    }
    setBusy(true);
    try {
      const parsed = JSON.parse(verifierJson) as Record<string, unknown>;
      const res = await verifyBundlePayload(actor, {
        manifest: parsed,
        expected_manifest_sha256: expectedManifestSha.trim() || undefined,
      });
      setBundleVerifyResult(res);
      onNotify(res.message, !res.valid);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Payload verification failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyAuditChain() {
    setBusy(true);
    try {
      const res = await verifyAuditChain(actor);
      onChainVerified(res);
      onNotify(res.message, !res.valid);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Audit chain check failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleScrubText(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await redactPiiText(actor, piiInput);
      setPiiResult(res);
      onNotify(`Redacted ${res.total_redactions} sensitive token(s).`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'PII redaction failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <FileArchive className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-bold text-slate-900">
            Compile SHA-256 Hash-Chained Evidence Bundle
          </h2>
        </div>

        <form onSubmit={handleCompileBundle} className="mt-3 flex flex-wrap items-center gap-3">
          <input
            required
            aria-label="Evidence Bundle Name"
            value={bundleName}
            onChange={(e) => setBundleName(e.target.value)}
            className="min-w-[240px] flex-1 rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <div className="flex items-center gap-2">
            {(['SOC2', 'HIPAA', 'GDPR'] as const).map((fw) => (
              <label key={fw} className="inline-flex items-center gap-1 text-xs font-medium">
                <input
                  type="checkbox"
                  checked={frameworks.includes(fw)}
                  onChange={() => toggleFramework(fw)}
                />
                {fw}
              </label>
            ))}
          </div>
          <button
            type="submit"
            disabled={busy || !canWrite}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            Compile &amp; Queue Release
          </button>
        </form>

        <div className="mt-4 space-y-2.5">
          {bundles.map((b) => (
            <div
              key={b.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-bold text-slate-900">{b.bundle_name}</span>
                  <StatusBadge status={b.status} />
                  <span className="text-slate-600">{b.item_count} items</span>
                </div>
                <p className="font-mono text-[11px] text-slate-500">
                  Head: {b.chain_head_hash.slice(0, 16)}... · Manifest:{' '}
                  {b.manifest_sha256.slice(0, 16)}...
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => handleVerifyBundle(b.id)}
                  className="rounded border border-emerald-200 bg-emerald-50 px-2.5 py-1 font-semibold text-emerald-700 hover:bg-emerald-100"
                >
                  Verify
                </button>
                <button
                  type="button"
                  onClick={() => handleLoadBundleIntoVerifier(b.id)}
                  className="rounded border border-indigo-200 bg-indigo-50 px-2.5 py-1 font-semibold text-indigo-700 hover:bg-indigo-100"
                >
                  Inspect in Verifier
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadBundle(b.id)}
                  className="inline-flex items-center gap-1 rounded border border-slate-300 bg-white px-2.5 py-1 font-semibold text-slate-700 hover:bg-slate-100"
                >
                  <Download className="h-3 w-3" />
                  Export JSON
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Independent Tamper-Detection Verifier
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {bundles.length > 0 && (
              <button
                type="button"
                onClick={() => handleLoadBundleIntoVerifier(bundles[0].id)}
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50"
              >
                Load Latest Bundle
              </button>
            )}
            <button
              type="button"
              onClick={handleSimulateTamper}
              className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1 text-xs font-semibold text-rose-700 hover:bg-rose-100"
            >
              Simulate 1-Field Tamper
            </button>
            <button
              type="button"
              onClick={handleVerifyPayload}
              className="rounded-lg bg-emerald-600 px-3 py-1 text-xs font-semibold text-white hover:bg-emerald-700"
            >
              Verify Manifest Payload
            </button>
          </div>
        </div>

        <input
          type="text"
          aria-label="Expected Manifest SHA-256"
          placeholder="Optional expected manifest_sha256..."
          value={expectedManifestSha}
          onChange={(e) => setExpectedManifestSha(e.target.value)}
          className="mt-3 w-full rounded-lg border border-slate-300 px-3 py-1.5 font-mono text-xs"
        />
        <textarea
          rows={5}
          aria-label="Manifest JSON Payload"
          placeholder="Load an exported bundle or paste manifest JSON here..."
          value={verifierJson}
          onChange={(e) => setVerifierJson(e.target.value)}
          className="mt-2 w-full rounded-lg border border-slate-300 p-2.5 font-mono text-[11px]"
        />

        {bundleVerifyResult && (
          <div
            className={`mt-3 rounded-lg border p-3 text-xs ${
              bundleVerifyResult.valid
                ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
                : 'border-rose-200 bg-rose-50 text-rose-800'
            }`}
          >
            <div className="flex items-center gap-2 font-bold">
              {bundleVerifyResult.valid ? (
                <CheckCircle2 className="h-4 w-4" />
              ) : (
                <ShieldAlert className="h-4 w-4" />
              )}
              <span>{bundleVerifyResult.message}</span>
            </div>
            {bundleVerifyResult.errors.length > 0 && (
              <ul className="mt-1 list-disc pl-5">
                {bundleVerifyResult.errors.map((errMsg, idx) => (
                  <li key={idx}>{errMsg}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-slate-900">
              Immutable SHA-256 Audit Trail ({auditEvents.length} shown)
            </h3>
            {chainStatus && (
              <p
                className={`mt-0.5 text-xs font-medium ${
                  chainStatus.valid ? 'text-emerald-700' : 'text-rose-700'
                }`}
              >
                {chainStatus.message} (Head: {chainStatus.head_hash.slice(0, 14)}...)
              </p>
            )}
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={handleVerifyAuditChain}
            className="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-1.5 text-xs font-semibold text-indigo-700 hover:bg-indigo-100"
          >
            Verify Audit Chain
          </button>
        </div>

        <div className="mt-3 max-h-72 overflow-y-auto divide-y divide-slate-100 rounded-lg border border-slate-200">
          {auditEvents.slice(0, 30).map((ev) => (
            <div key={ev.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-xs">
              <div>
                <span className="mr-2 font-mono font-bold text-slate-800">#{ev.sequence_no}</span>
                <span className="font-semibold text-indigo-700">{ev.event_type}</span>
                <span className="mx-1.5 text-slate-400">·</span>
                <span className="text-slate-600">{ev.actor_email}</span>
              </div>
              <span className="font-mono text-[11px] text-slate-500">
                {ev.event_hash.slice(0, 14)}...
              </span>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-indigo-600" />
          <h3 className="text-sm font-bold text-slate-900">
            Compliance PII, PHI &amp; Secret Redaction Sandbox
          </h3>
        </div>
        <form onSubmit={handleScrubText} className="mt-3 space-y-2.5">
          <textarea
            rows={3}
            aria-label="Sample Text for PII Redaction"
            value={piiInput}
            onChange={(e) => setPiiInput(e.target.value)}
            className="w-full rounded-lg border border-slate-300 p-2.5 font-mono text-xs"
          />
          <button
            type="submit"
            disabled={busy}
            className="rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
          >
            Scrub Sensitive Identifiers
          </button>
        </form>
        {piiResult && (
          <div className="mt-3 space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs">
            <p className="font-semibold text-slate-800">
              Redacted Output ({piiResult.total_redactions} redactions):
            </p>
            <pre className="overflow-x-auto rounded bg-slate-900 p-2.5 font-mono text-[11px] text-emerald-300">
              {piiResult.redacted_text}
            </pre>
            <div className="flex flex-wrap gap-1.5">
              {piiResult.findings.map((f) => (
                <span
                  key={f.category}
                  className="rounded border border-indigo-200 bg-indigo-50 px-2 py-0.5 font-mono text-[11px] text-indigo-700"
                >
                  {f.category}: {f.count}
                </span>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
