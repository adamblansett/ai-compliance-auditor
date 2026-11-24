interface StatusBadgeProps {
  status: string;
}

const STYLE_MAP: Record<string, string> = {
  passing: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  pass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  passed: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  approved: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  approved_released: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  compliant: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  completed: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  released: 'bg-slate-100 text-slate-700 border-slate-300',
  low: 'bg-slate-100 text-slate-700 border-slate-200',

  failing: 'bg-rose-50 text-rose-700 border-rose-200',
  fail: 'bg-rose-50 text-rose-700 border-rose-200',
  failed: 'bg-rose-50 text-rose-700 border-rose-200',
  rejected: 'bg-rose-50 text-rose-700 border-rose-200',
  violation_over_retained: 'bg-rose-50 text-rose-700 border-rose-200',
  blocked_by_legal_hold: 'bg-rose-50 text-rose-700 border-rose-200',
  critical: 'bg-rose-50 text-rose-700 border-rose-200',
  high: 'bg-orange-50 text-orange-700 border-orange-200',

  warning: 'bg-amber-50 text-amber-800 border-amber-200',
  warnings: 'bg-amber-50 text-amber-800 border-amber-200',
  pending: 'bg-amber-50 text-amber-800 border-amber-200',
  pending_approval: 'bg-amber-50 text-amber-800 border-amber-200',
  medium: 'bg-amber-50 text-amber-800 border-amber-200',
  active: 'bg-amber-50 text-amber-800 border-amber-200',
  in_review: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  received: 'bg-sky-50 text-sky-700 border-sky-200',

  waived: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  exception_granted: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  legal_hold_suspended: 'bg-violet-50 text-violet-700 border-violet-200',
  not_evaluated: 'bg-slate-100 text-slate-600 border-slate-200',
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const key = status.toLowerCase();
  const classes = STYLE_MAP[key] || 'bg-slate-100 text-slate-700 border-slate-200';
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold capitalize ${classes}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
}
