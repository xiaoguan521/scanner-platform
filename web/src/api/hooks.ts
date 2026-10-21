import { useEffect, useState } from 'react';
import { apiClient, isDemoMode } from './client';
import type { DashboardSummary, Resources, SystemStatus, Capabilities } from './client';

export function useCollection<K extends keyof Resources>(name: K, demoFixtures: Resources[K][], query = '', enabled = true) {
  const [data, setData] = useState<Resources[K][]>(() => isDemoMode && enabled ? [...demoFixtures] : []);
  const [loading, setLoading] = useState(!isDemoMode && enabled);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isDemoMode || !enabled) return;
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
    const pollInterval = name === 'assets' ? 10_000 : name === 'scopes' ? 60_000 : ['tasks','findings','nodes','rules','schedules','rule-jobs','custom-rules'].includes(name) ? 1000 : undefined;
    const timer = pollInterval === undefined ? undefined : window.setInterval(load, pollInterval);
    return () => {
      controller.abort();
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [name, query, enabled]);
  return { data, setData, loading, error };
}

export function useDashboardSummary(days: 7 | 30 | 90) {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(!isDemoMode);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (isDemoMode) return;
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
    const timer = window.setInterval(load, 5000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [days]);
  return { data, loading, error };
}

export function useSystemStatus() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (isDemoMode) return;
    const controller = new AbortController();
    const load=()=>Promise.all([apiClient.systemStatus(controller.signal), apiClient.capabilities(controller.signal)])
      .then(([nextStatus,nextCapabilities])=>{if(!controller.signal.aborted){setStatus(nextStatus);setCapabilities(nextCapabilities);setError(null);}})
      .catch((cause:unknown)=>{if(!controller.signal.aborted){setStatus(null);setError(cause instanceof Error?cause.message:'Server unavailable');}});
    void load(); const timer=window.setInterval(()=>void load(),3000);
    return () => {controller.abort();window.clearInterval(timer);};
  }, []);
  return { status, capabilities, error };
}
