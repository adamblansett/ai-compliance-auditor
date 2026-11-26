import { FormEvent, useState } from 'react';
import { Bell, Check, RefreshCw, Trash2, Webhook } from 'lucide-react';
import {
  acknowledgeAlert,
  createWebhook,
  deleteWebhook,
  evaluateDriftAlerts,
  resolveAlert,
} from '../api/client';
import { StatusBadge } from './StatusBadge';
import type {
  ActorContext,
  AlertEventItem,
  AlertWebhookItem,
} from '../types/compliance';

interface AlertsViewProps {
  actor: ActorContext;
  alerts: AlertEventItem[];
  webhooks: AlertWebhookItem[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, isError?: boolean) => void;
}

export function AlertsView({
  actor,
  alerts,
  webhooks,
  onRefresh,
  onNotify,
}: AlertsViewProps) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [hookName, setHookName] = useState('');
  const [hookUrl, setHookUrl] = useState('');
  const [hookEvents, setHookEvents] = useState('control_regression, dsar_overdue, waiver_expiring');
  const [busy, setBusy] = useState(false);

  const canWrite = actor.role !== 'viewer';
  const isOfficer = actor.role === 'compliance_officer' || actor.role === 'admin';

  const filtered = alerts.filter((a) => statusFilter === 'all' || a.status === statusFilter);

  async function handleEvaluate() {
    setBusy(true);
    try {
      const opened = await evaluateDriftAlerts(actor);
      onNotify(`Drift evaluation complete: ${opened.length} new alert(s) opened.`);
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Alert evaluation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleAck(alertId: string) {
    setBusy(true);
    try {
      await acknowledgeAlert(actor, alertId);
      onNotify('Alert acknowledged.');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Acknowledge failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleResolve(alertId: string) {
    setBusy(true);
    try {
      await resolveAlert(actor, alertId);
      onNotify('Alert resolved.');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Resolve failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleAddWebhook(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const created = await createWebhook(actor, {
        name: hookName,
        target_url: hookUrl,
        event_types: hookEvents
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      });
      onNotify(`Registered signed webhook '${created.name}'.`);
      setHookName('');
      setHookUrl('');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Webhook creation failed', true);
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteWebhook(webhookId: string) {
    setBusy(true);
    try {
      await deleteWebhook(actor, webhookId);
      onNotify('Deleted webhook subscription.');
      await onRefresh();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Webhook delete failed', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-rose-600" />
          <h2 className="text-sm font-bold text-slate-900">
            Continuous Drift &amp; SLA Alerts ({filtered.length})
          </h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Filter Alerts by Status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
          <button
            type="button"
            disabled={busy || !canWrite}
            onClick={handleEvaluate}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Evaluate Drift Alerts
          </button>
        </div>
      </section>

      <div className="space-y-2.5">
        {filtered.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white p-6 text-center text-xs text-slate-500">
            No alerts match the current filter.
          </div>
        ) : (
          filtered.map((a) => (
            <article
              key={a.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4 text-xs shadow-sm"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={a.severity} />
                  <StatusBadge status={a.status} />
                  <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700">
                    {a.alert_type}
                  </span>
                  <span className="font-bold text-slate-900">{a.title}</span>
                </div>
                <p className="text-slate-600">{a.detail}</p>
              </div>
              <div className="flex gap-2">
                {canWrite && a.status === 'open' && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleAck(a.id)}
                    className="rounded border border-slate-300 bg-white px-2.5 py-1 font-semibold text-slate-700 hover:bg-slate-50"
                  >
                    Acknowledge
                  </button>
                )}
                {isOfficer && a.status !== 'resolved' && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleResolve(a.id)}
                    className="inline-flex items-center gap-1 rounded bg-emerald-600 px-2.5 py-1 font-semibold text-white hover:bg-emerald-700"
                  >
                    <Check className="h-3 w-3" />
                    Resolve
                  </button>
                )}
              </div>
            </article>
          ))
        )}
      </div>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex items-center gap-2">
          <Webhook className="h-4 w-4 text-indigo-600" />
          <h3 className="text-sm font-bold text-slate-900">
            HMAC-Signed Alert Webhooks ({webhooks.length})
          </h3>
        </div>
        <form onSubmit={handleAddWebhook} className="mt-3 grid gap-2 sm:grid-cols-4">
          <input
            required
            placeholder="Webhook Name (e.g. PagerDuty SecOps)"
            value={hookName}
            onChange={(e) => setHookName(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <input
            required
            placeholder="https://hooks.example.com/compliance"
            value={hookUrl}
            onChange={(e) => setHookUrl(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <input
            placeholder="Event types (comma-separated)"
            value={hookEvents}
            onChange={(e) => setHookEvents(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
          <button
            type="submit"
            disabled={busy || !isOfficer}
            className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
          >
            Add Signed Webhook
          </button>
        </form>

        {webhooks.length > 0 && (
          <div className="mt-3 space-y-2">
            {webhooks.map((h) => (
              <div
                key={h.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs"
              >
                <div>
                  <span className="font-bold text-slate-900">{h.name}</span>
                  <span className="ml-2 font-mono text-[11px] text-slate-600">{h.target_url}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">
                    Last: {h.last_delivery_status || 'pending'}
                  </span>
                  {isOfficer && (
                    <button
                      type="button"
                      onClick={() => handleDeleteWebhook(h.id)}
                      aria-label={`Delete webhook ${h.name}`}
                      className="rounded border border-rose-200 bg-rose-50 p-1 text-rose-700 hover:bg-rose-100"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
