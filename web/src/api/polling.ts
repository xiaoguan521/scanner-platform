export const pollIntervals = {
  activeTask: 3000,
  dashboard: 10_000,
  systemStatus: 15_000,
  schedules: 15_000,
  assetInsights: 10_000,
  reference: 60_000,
} as const;

type VisibilityTarget = { hidden: boolean; addEventListener(type: 'visibilitychange', listener: () => void): void; removeEventListener(type: 'visibilitychange', listener: () => void): void };
export interface PollingEnv {
  document?: VisibilityTarget;
  setInterval(handler: () => void, ms: number): number;
  clearInterval(id: number): void;
}

const browserEnv = (): PollingEnv => ({
  document: typeof document === 'undefined' ? undefined : document,
  setInterval: (handler, ms) => window.setInterval(handler, ms),
  clearInterval: id => window.clearInterval(id),
});

// Repeats load every intervalMs while the page is visible, and once more as
// soon as it becomes visible again. The caller performs the initial load.
export function pollWhileVisible(load: () => void, intervalMs: number, env: PollingEnv = browserEnv()): () => void {
  const visible = () => !env.document?.hidden;
  const timer = env.setInterval(() => { if (visible()) load(); }, intervalMs);
  const onVisibilityChange = () => { if (visible()) load(); };
  env.document?.addEventListener('visibilitychange', onVisibilityChange);
  return () => {
    env.clearInterval(timer);
    env.document?.removeEventListener('visibilitychange', onVisibilityChange);
  };
}
