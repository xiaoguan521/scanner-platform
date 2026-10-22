import { useEffect, useState } from 'react';
import { apiClient } from './client';
import { pollIntervals, pollWhileVisible } from './polling';
import type { DashboardSummary, Resources, SystemStatus, Capabilities } from './client';
import type { ScanTask } from '../types';

// Collections are loaded once unless the caller opts into polling. Unpaged
// collection endpoints return every record, so poll them sparingly.
export function useCollection<K extends keyof Resources>(name: K, query = '', enabled = true, pollMs?: number) {
  const [data, setData] = useState<Resources[K][]>([]);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    setLoading(true);
    let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      apiClient.collection(name, controller.signal, query).then((response) => {
      if (!controller.signal.aborted) {
        setData(response.items);
        setError(null);
      }
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) {
        setData([]);
        setError(cause instanceof Error ? cause.message : 'API unavailable');
      }
    }).finally(() => {
      inFlight = false;
      if (!controller.signal.aborted) setLoading(false);
    });
    };
    load();
    const stop = pollMs === undefined ? undefined : pollWhileVisible(load, pollMs);
    return () => {
      controller.abort();
      stop?.();
    };
  }, [name, query, enabled, pollMs]);
  return { data, setData, loading, error };
}

export function useDashboardSummary(days: 7 | 30 | 90) {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      apiClient.dashboardSummary(days, controller.signal).then((next) => {
        if (!controller.signal.aborted) { setData(next); setError(null); }
      }).catch((cause: unknown) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : '总览聚合不可用');
      }).finally(() => { inFlight = false; if (!controller.signal.aborted) setLoading(false); });
    };
    load();
    const stop = pollWhileVisible(load, pollIntervals.dashboard);
    return () => { controller.abort(); stop(); };
  }, [days]);
  return { data, loading, error };
}

export function useSystemStatus() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    // Capabilities are fixed for the Server process; only status is refreshed.
    void apiClient.capabilities(controller.signal).then(next=>{if(!controller.signal.aborted)setCapabilities(next);}).catch(()=>undefined);
    const load=()=>apiClient.systemStatus(controller.signal)
      .then(nextStatus=>{if(!controller.signal.aborted){setStatus(nextStatus);setError(null);}})
      .catch((cause:unknown)=>{if(!controller.signal.aborted){setStatus(null);setError(cause instanceof Error?cause.message:'Server unavailable');}});
    void load(); const stop=pollWhileVisible(()=>void load(),pollIntervals.systemStatus);
    return () => {controller.abort();stop();};
  }, []);
  return { status, capabilities, error };
}

export function useRecentTasks(limit = 10) {
  const [data, setData] = useState<ScanTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      apiClient.tasksPage(1, limit, {}, controller.signal).then((next) => {
        if (!controller.signal.aborted) { setData(next.items); setError(null); }
      }).catch((cause: unknown) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : '近期任务不可用');
      }).finally(() => { inFlight = false; if (!controller.signal.aborted) setLoading(false); });
    };
    load();
    const stop = pollWhileVisible(load, pollIntervals.dashboard);
    return () => { controller.abort(); stop(); };
  }, [limit]);
  return { data, loading, error };
}
