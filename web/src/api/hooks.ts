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
    apiClient.collection(name, controller.signal).then((response) => {
      if (!controller.signal.aborted) setData(response.items);
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) {
        setData([]);
        setError(cause instanceof Error ? cause.message : 'API unavailable');
      }
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
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
    Promise.all([apiClient.systemStatus(controller.signal), apiClient.capabilities(controller.signal)])
      .then(([nextStatus, nextCapabilities]) => {
        if (!controller.signal.aborted) {
          setStatus(nextStatus);
          setCapabilities(nextCapabilities);
        }
      }).catch((cause: unknown) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Server unavailable');
      });
    return () => controller.abort();
  }, []);
  return { status, capabilities, error };
}
