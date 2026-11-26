import { FormEvent, useState } from 'react';
import { BookOpen, Search, Upload } from 'lucide-react';
import { ingestPolicyDocument, queryPolicyRag } from '../api/client';
import type {
  ActorContext,
  PolicyDocumentItem,
  RagQueryResponse,
} from '../types/compliance';

interface PolicyRagViewProps {
  actor: ActorContext;
  documents: PolicyDocumentItem[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

export function PolicyRagView({
  actor,
  documents,
  onRefresh,
  onNotify,
}: PolicyRagViewProps) {
  const [title, setTitle] = useState('Access Control & Key Rotation SOP');
  const [filename, setFilename] = useState('access-key-sop.md');
  const [framework, setFramework] = useState<'SOC2' | 'HIPAA' | 'GDPR' | 'ALL'>('ALL');
  const [version, setVersion] = useState('1.0');
  const [content, setContent] = useState(
    '# Encryption & Key Management\nAll production databases enforce AES-256-GCM at rest and TLS 1.3 in transit with annual KMS key rotation.\n\n# Breach Notification\nConfirmed personal data breaches trigger supervisory notification within 72 hours.',
  );
  const [queryText, setQueryText] = useState('What is our 72-hour breach notification and TLS requirement?');
  const [queryFramework, setQueryFramework] = useState('ALL');
  const [ragResult, setRagResult] = useState<RagQueryResponse | null>(null);
  const [busy, setBusy] = useState(false);

  const canWrite = actor.role !== 'viewer';

  async function handleIngest(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const doc = await ingestPolicyDocument(actor, {
        title,
        filename,
        framework,
        version,
        content,
      });
      onNotify(
        `Indexed '${doc.title}' (${doc.chunk_count} chunks, ${doc.pii_redaction_count} PII redactions).`,
      );
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Policy ingestion failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleQuery(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await queryPolicyRag(actor, {
        query: queryText,
        framework: queryFramework === 'ALL' ? undefined : queryFramework,
        top_k: 4,
      });
      setRagResult(res);
      onNotify(`Retrieved ${res.citations.length} grounded policy citation(s).`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Policy RAG query failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <Search className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-bold text-slate-900">
            Citation-Grounded Policy RAG Q&amp;A
          </h2>
        </div>
        <p className="mt-1 text-xs text-slate-600">
          Ask compliance questions across uploaded SOPs and policies. Answers cite exact indexed
          sections and auto-mapped SOC 2, HIPAA, and GDPR controls with PII scrubbing.
        </p>

        <form onSubmit={handleQuery} className="mt-3 flex flex-wrap gap-2">
          <input
            required
            aria-label="Policy RAG Question"
            value={queryText}
            onChange={(e) => setQueryText(e.target.value)}
            placeholder="Ask about breach notification SLAs, encryption, DSAR holds..."
            className="min-w-[260px] flex-1 rounded-lg border border-slate-300 px-3 py-2 text-xs"
          />
          <select
            aria-label="Query Framework Scope"
            value={queryFramework}
            onChange={(e) => setQueryFramework(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-2 text-xs"
          >
            <option value="ALL">All Frameworks</option>
            <option value="SOC2">SOC 2</option>
            <option value="HIPAA">HIPAA</option>
            <option value="GDPR">GDPR</option>
          </select>
          <button
            type="submit"
            disabled={busy}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            Query Policies
          </button>
        </form>

        {ragResult && (
          <div className="mt-4 space-y-3 rounded-xl border border-indigo-100 bg-indigo-50/50 p-4 text-xs">
            <div>
              <p className="font-bold text-slate-900">
                Grounded Answer ({ragResult.llm_provider})
              </p>
              <p className="mt-1 text-slate-800">{ragResult.answer}</p>
            </div>
            <div className="space-y-2">
              <p className="font-semibold text-slate-700">
                Citations ({ragResult.citations.length})
              </p>
              {ragResult.citations.map((c) => (
                <div
                  key={c.chunk_id}
                  className="rounded-lg border border-slate-200 bg-white p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-bold text-slate-900">
                      {c.document_title} · {c.section_heading}
                    </span>
                    <span className="font-mono text-[11px] text-indigo-700">
                      score: {c.score.toFixed(3)}
                    </span>
                  </div>
                  <p className="mt-1 text-slate-600">{c.excerpt}</p>
                  {c.mapped_controls.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {c.mapped_controls.map((code) => (
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
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <Upload className="h-4 w-4 text-indigo-600" />
          <h3 className="text-sm font-bold text-slate-900">
            Index Policy / SOP Document
          </h3>
        </div>
        <form onSubmit={handleIngest} className="mt-3 space-y-3">
          <div className="grid gap-2.5 sm:grid-cols-4">
            <input
              required
              aria-label="Policy Document Title"
              placeholder="Document Title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
            />
            <input
              required
              aria-label="Policy Filename"
              placeholder="Filename"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
            />
            <select
              aria-label="Policy Framework"
              value={framework}
              onChange={(e) =>
                setFramework(e.target.value as 'SOC2' | 'HIPAA' | 'GDPR' | 'ALL')
              }
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
            >
              <option value="ALL">All Frameworks</option>
              <option value="SOC2">SOC 2</option>
              <option value="HIPAA">HIPAA</option>
              <option value="GDPR">GDPR</option>
            </select>
            <input
              required
              aria-label="Policy Version"
              placeholder="Version"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
            />
          </div>
          <textarea
            rows={4}
            aria-label="Policy Markdown Content"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="w-full rounded-lg border border-slate-300 p-2.5 font-mono text-xs"
          />
          <button
            type="submit"
            disabled={busy || !canWrite}
            className="rounded-lg bg-slate-900 px-4 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
          >
            Index Policy with PII Scrubbing
          </button>
        </form>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-indigo-600" />
          <h3 className="text-sm font-bold text-slate-900">
            Indexed Policy Corpus ({documents.length})
          </h3>
        </div>
        <div className="mt-3 space-y-2">
          {documents.length === 0 ? (
            <p className="text-xs text-slate-500">No policy documents indexed yet.</p>
          ) : (
            documents.map((doc) => (
              <div
                key={doc.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs"
              >
                <div>
                  <span className="font-bold text-slate-900">{doc.title}</span>
                  <span className="ml-2 rounded border border-slate-200 bg-white px-2 py-0.5 text-[11px] font-semibold text-slate-700">
                    {doc.framework} · v{doc.version}
                  </span>
                </div>
                <div className="text-slate-600">
                  {doc.chunk_count} chunks · {doc.pii_redaction_count} PII scrubbed ·{' '}
                  <span className="font-mono">{doc.document_sha256.slice(0, 12)}...</span>
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
