import React, { createContext, useContext, useEffect, useState } from 'react';
import { apiClient, errorMessage } from './client';
import { pollIntervals, pollWhileVisible } from './polling';
import { useQuery } from './query';
import type { Resources, SystemStatus, Capabilities } from './client';

// Collections are loaded once unless the caller opts into polling. Unpaged
// collection endpoints return every record, so poll them sparingly.
export function useCollection<K extends keyof Resources>(name: K, query = '', enabled = true, pollMs?: number) {
  const { data, setData, loading, error } = useQuery<Resources[K][]>(signal => apiClient.collection(name, signal, query).then(response => response.items), [name, query], { pollMs, enabled, emptyValue: [], errorFallback: 'API unavailable' });
  const setItems = setData as React.Dispatch<React.SetStateAction<Resources[K][]>>;
  return { data: data ?? [], setData: setItems, loading, error };
}

export function useDashboardSummary(days: 7 | 30 | 90) {
  const { data, loading, error } = useQuery(signal => apiClient.dashboardSummary(days, signal), [days], { pollMs: pollIntervals.dashboard, errorFallback: '总览聚合不可用' });
  return { data: data ?? null, loading, error };
}

export interface SystemStatusState { status: SystemStatus | null; capabilities: Capabilities | null; error: string | null }
// AppLayout owns the single status poller and shares it with pages.
export const SystemStatusContext = createContext<SystemStatusState>({ status: null, capabilities: null, error: null });
export function useServerCapability(name: string): boolean {
  const { status, capabilities } = useContext(SystemStatusContext);
  return Boolean(status?.enabled.includes(name) || capabilities?.enabled.includes(name));
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
      .catch((cause:unknown)=>{if(!controller.signal.aborted){setStatus(null);setError(errorMessage(cause,'Server unavailable'));}});
    void load(); const stop=pollWhileVisible(()=>void load(),pollIntervals.systemStatus);
    return () => {controller.abort();stop();};
  }, []);
  return { status, capabilities, error };
}

export function useRecentTasks(limit = 10) {
  const { data, loading, error } = useQuery(signal => apiClient.tasksPage(1, limit, {}, signal).then(next => next.items), [limit], { pollMs: pollIntervals.dashboard, errorFallback: '近期任务不可用' });
  return { data: data ?? [], loading, error };
}
