import { useState, useEffect, useCallback } from 'react';
import {
  MessageSquare, RefreshCw, RotateCcw, Trash2, Search,
  CheckCircle, Clock, AlertTriangle, ArrowUpRight, ArrowDownLeft,
} from 'lucide-react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { smsApi, type SmsCdrRecord, type SmsQueueItem, type SmsInspectorData } from '../../api/sms';

export function SmsInspectorView() {
  const [data, setData] = useState<SmsInspectorData | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [directionFilter, setDirectionFilter] = useState<'all' | 'MO' | 'MT'>('all');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [acting, setActing] = useState(false);

  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await smsApi.getInspector();
      if (res.success) {
        setData(res);
      }
    } catch {
      if (!silent) toast.error('Failed to load SMS inspector data');
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => loadData(true), 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, loadData]);

  const handleResetCounter = async () => {
    if (!window.confirm('Reset the cumulative SIP MESSAGE request counter to 0?')) return;
    setActing(true);
    try {
      const res = await smsApi.resetCounter();
      if (res.success) {
        toast.success('SMS counter reset to 0');
        await loadData(true);
      } else {
        toast.error(res.error || 'Failed to reset counter');
      }
    } catch (err: any) {
      toast.error(`Reset failed: ${err?.message || 'Error'}`);
    } finally {
      setActing(false);
    }
  };

  const handleClearQueue = async () => {
    if (!window.confirm('Clear all pending in-flight messages from the store-and-forward queue?')) return;
    setActing(true);
    try {
      const res = await smsApi.clearQueue();
      if (res.success) {
        toast.success('In-flight message queue cleared');
        await loadData(true);
      } else {
        toast.error(res.error || 'Failed to clear queue');
      }
    } catch (err: any) {
      toast.error(`Clear failed: ${err?.message || 'Error'}`);
    } finally {
      setActing(false);
    }
  };

  const filteredRecords = (data?.records || []).filter((r: SmsCdrRecord) => {
    if (directionFilter !== 'all' && r.direction !== directionFilter) return false;
    if (!search.trim()) return true;
    const term = search.toLowerCase();
    return (
      r.sender.toLowerCase().includes(term) ||
      r.recipient.toLowerCase().includes(term) ||
      (r.text && r.text.toLowerCase().includes(term))
    );
  });

  return (
    <div className="space-y-4">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SIP Message Counter Card */}
        <div className="nms-card bg-nms-surface-2 border border-nms-border p-4 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-nms-text-dim uppercase tracking-wider">SIP Messages Counter</span>
              <MessageSquare className="w-4 h-4 text-nms-accent" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-nms-text">
                {data?.stats?.cumulativeSmsTotal ?? '—'}
              </span>
              <span className="text-xs text-nms-text-dim">requests tracked</span>
            </div>
            <p className="text-xs text-nms-text-dim mt-2 leading-relaxed">
              Total SIP MESSAGE packets received by S-CSCF / SMSC. Modem retry loops inflate this counter.
            </p>
          </div>
          <div className="pt-3 mt-3 border-t border-nms-border flex justify-end">
            <button
              onClick={handleResetCounter}
              disabled={acting || (data?.stats?.cumulativeSmsTotal === 0)}
              className="nms-btn-ghost text-xs flex items-center gap-1.5 px-2.5 py-1 text-nms-text-dim hover:text-amber-400 disabled:opacity-40"
            >
              <RotateCcw className="w-3 h-3" /> Reset to 0
            </button>
          </div>
        </div>

        {/* In-Flight Store-and-Forward Queue */}
        <div className="nms-card bg-nms-surface-2 border border-nms-border p-4 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-nms-text-dim uppercase tracking-wider">In-Flight Queue</span>
              <Clock className={clsx('w-4 h-4', (data?.queue?.length ?? 0) > 0 ? 'text-amber-400' : 'text-green-400')} />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className={clsx('text-3xl font-bold font-mono', (data?.queue?.length ?? 0) > 0 ? 'text-amber-400' : 'text-green-400')}>
                {data?.queue?.length ?? 0}
              </span>
              <span className="text-xs text-nms-text-dim">pending delivery</span>
            </div>
            <p className="text-xs text-nms-text-dim mt-2 leading-relaxed">
              {(data?.queue?.length ?? 0) > 0
                ? 'Messages waiting for recipient registration or acknowledgment.'
                : 'All messages delivered. No messages currently pending in queue.'}
            </p>
          </div>
          <div className="pt-3 mt-3 border-t border-nms-border flex justify-end">
            {(data?.queue?.length ?? 0) > 0 ? (
              <button
                onClick={handleClearQueue}
                disabled={acting}
                className="nms-btn-ghost text-xs flex items-center gap-1.5 px-2.5 py-1 text-red-400 hover:bg-red-500/10"
              >
                <Trash2 className="w-3 h-3" /> Clear Queue
              </button>
            ) : (
              <span className="text-xs text-green-400 flex items-center gap-1 py-1">
                <CheckCircle className="w-3 h-3" /> Queue Clear
              </span>
            )}
          </div>
        </div>

        {/* Permanent SMS CDRs */}
        <div className="nms-card bg-nms-surface-2 border border-nms-border p-4 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-nms-text-dim uppercase tracking-wider">SMS Detail Records</span>
              <CheckCircle className="w-4 h-4 text-nms-accent" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-bold font-mono text-nms-text">
                {data?.records?.length ?? 0}
              </span>
              <span className="text-xs text-nms-text-dim">historical records</span>
            </div>
            <p className="text-xs text-nms-text-dim mt-2 leading-relaxed">
              Permanent logging in MariaDB (<span className="font-mono text-nms-text">smsc.sms_cdr</span>) capturing timestamps, sender, recipient, and delivery status.
            </p>
          </div>
          <div className="pt-3 mt-3 border-t border-nms-border flex justify-end">
            <span className="text-xs text-nms-text-dim py-1 font-mono">
              MariaDB smsc.sms_cdr
            </span>
          </div>
        </div>
      </div>

      {/* In-Flight Queue Details (if any pending) */}
      {data?.queue && data.queue.length > 0 && (
        <div className="nms-card border border-amber-500/30 bg-amber-500/5 p-4 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              Active In-Flight Queue ({data.queue.length} messages retry loop)
            </div>
            <button
              onClick={handleClearQueue}
              disabled={acting}
              className="text-xs px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 flex items-center gap-1"
            >
              <Trash2 className="w-3 h-3" /> Drop Queue
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-nms-text-dim border-b border-nms-border/50">
                <tr>
                  <th className="py-2 px-3">ID</th>
                  <th className="py-2 px-3">Valid Until</th>
                  <th className="py-2 px-3">From</th>
                  <th className="py-2 px-3">To</th>
                  <th className="py-2 px-3">Content</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-nms-border/30 font-mono">
                {data.queue.map((item: SmsQueueItem) => (
                  <tr key={item.id} className="hover:bg-nms-surface-2/40">
                    <td className="py-2 px-3 text-nms-text-dim">#{item.id}</td>
                    <td className="py-2 px-3 text-nms-text-dim">{item.valid}</td>
                    <td className="py-2 px-3 text-nms-text">{item.caller}</td>
                    <td className="py-2 px-3 text-nms-text">{item.callee}</td>
                    <td className="py-2 px-3 text-amber-200">{item.text}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SMS CDR History Table */}
      <div className="nms-card bg-nms-surface border border-nms-border rounded-xl p-4 space-y-4">
        {/* Controls Toolbar */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="w-4 h-4 text-nms-text-dim absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search sender, recipient, text..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="pl-9 pr-3 py-1.5 text-xs bg-nms-surface-2 border border-nms-border rounded-lg text-nms-text placeholder-nms-text-dim w-64 focus:outline-none focus:border-nms-accent"
              />
            </div>
            <div className="flex rounded-lg border border-nms-border p-0.5 bg-nms-surface-2">
              <button
                onClick={() => setDirectionFilter('all')}
                className={clsx('px-2.5 py-1 text-xs rounded-md font-medium transition-all', directionFilter === 'all' ? 'bg-nms-accent text-nms-accent-fg' : 'text-nms-text-dim hover:text-nms-text')}
              >
                All
              </button>
              <button
                onClick={() => setDirectionFilter('MO')}
                className={clsx('px-2.5 py-1 text-xs rounded-md font-medium transition-all flex items-center gap-1', directionFilter === 'MO' ? 'bg-nms-accent text-nms-accent-fg' : 'text-nms-text-dim hover:text-nms-text')}
              >
                <ArrowUpRight className="w-3 h-3" /> MO (Sent)
              </button>
              <button
                onClick={() => setDirectionFilter('MT')}
                className={clsx('px-2.5 py-1 text-xs rounded-md font-medium transition-all flex items-center gap-1', directionFilter === 'MT' ? 'bg-nms-accent text-nms-accent-fg' : 'text-nms-text-dim hover:text-nms-text')}
              >
                <ArrowDownLeft className="w-3 h-3" /> MT (Received)
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-nms-text-dim cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={e => setAutoRefresh(e.target.checked)}
                className="rounded border-nms-border text-nms-accent focus:ring-0"
              />
              Live polling (5s)
            </label>
            <button
              onClick={() => loadData()}
              disabled={loading}
              className="nms-btn-ghost text-xs flex items-center gap-1.5 px-3 py-1.5 border border-nms-border rounded-lg text-nms-text hover:bg-nms-surface-2"
            >
              <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} /> Refresh
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-nms-surface-2/60 text-nms-text-dim border-b border-nms-border uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Direction</th>
                <th className="py-2.5 px-3">Sender</th>
                <th className="py-2.5 px-3">Recipient</th>
                <th className="py-2.5 px-3">Message Text</th>
                <th className="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-nms-border/40 font-mono">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-nms-text-dim font-sans">
                    {loading ? 'Loading SMS messages...' : 'No SMS CDR records found.'}
                  </td>
                </tr>
              ) : (
                filteredRecords.map((r: SmsCdrRecord) => (
                  <tr key={r.id} className="hover:bg-nms-surface-2/40 transition-colors">
                    <td className="py-2.5 px-3 whitespace-nowrap text-nms-text-dim">
                      {r.created_at}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={clsx(
                        'px-2 py-0.5 rounded-full text-[10px] font-semibold flex items-center gap-1 w-fit',
                        r.direction === 'MO' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-purple-500/10 text-purple-400 border border-purple-500/30',
                      )}>
                        {r.direction === 'MO' ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownLeft className="w-3 h-3" />}
                        {r.direction}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-nms-text font-bold whitespace-nowrap">{r.sender}</td>
                    <td className="py-2.5 px-3 text-nms-text font-bold whitespace-nowrap">{r.recipient}</td>
                    <td className="py-2.5 px-3 text-nms-text break-words max-w-md font-sans">
                      {r.text || <span className="text-nms-text-dim italic">(Empty body)</span>}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={clsx(
                        'px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase',
                        r.status === 'DELIVERED' && 'bg-green-500/10 text-green-400 border border-green-500/30',
                        r.status === 'QUEUED' && 'bg-amber-500/10 text-amber-400 border border-amber-500/30',
                        r.status === 'FAILED' && 'bg-red-500/10 text-red-400 border border-red-500/30',
                      )}>
                        {r.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

