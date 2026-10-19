import { useEffect, useState } from 'react';
import { apiClient, isDemoMode } from './client';
import type { Resources, SystemStatus, Capabilities } from './client';

export function useCollection<K extends keyof Resources>(name: K, demoFixtures: Resources[K][]) {
  const [data, setData] = useState<Resources[K][]>(() => isDemoMode ? [...demoFixtures] : []);
  const [loading, setLoading] = useState(!isDemoMode);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isDemoMode) return;
    const controller = new AbortController();
    setLoading(true);
    let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      apiClient.collection(name, controller.signal).then((response) => {
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
    const timer = ['tasks','findings','nodes','rules','schedules','rule-jobs','custom-rules'].includes(name) ? window.setInterval(load, 1000) : undefined;
    return () => {
      controller.abort();
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [name]);
  return { data, setData, loading, error };
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
