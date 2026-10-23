import { useCallback, useEffect, useRef, useState } from 'react';
import { errorMessage } from './errors';
import { pollWhileVisible } from './polling';

export interface QueryCallbacks<R> {
  fetch: (signal: AbortSignal) => Promise<R>;
  onData: (data: R) => void;
  onError: (message: string) => void;
  /** Called after the first request settles; later polls refresh silently. */
  onSettled: () => void;
  errorFallback: string;
  pollMs?: number;
  poll?: typeof pollWhileVisible;
}

// Runs one request now and, with pollMs, repeats it while the page is visible.
// Requests never overlap, and nothing is reported after the returned stop().
export function startQuery<R>({ fetch, onData, onError, onSettled, errorFallback, pollMs, poll = pollWhileVisible }: QueryCallbacks<R>): () => void {
  const controller = new AbortController();
  let inFlight = false;
  let settled = false;
  const load = () => {
    if (inFlight) return;
    inFlight = true;
    fetch(controller.signal).then(result => {
      if (!controller.signal.aborted) onData(result);
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) onError(errorMessage(cause, errorFallback));
    }).finally(() => {
      inFlight = false;
      if (!controller.signal.aborted && !settled) { settled = true; onSettled(); }
    });
  };
  load();
  const stop = pollMs === undefined ? undefined : poll(load, pollMs);
  return () => { controller.abort(); stop?.(); };
}

export interface QueryOptions<R> {
  pollMs?: number;
  errorFallback?: string;
  /** Value shown after a failed request; the previous data stays when omitted. */
  emptyValue?: R;
  enabled?: boolean;
}

/**
 * Loads `fetcher` whenever `key` changes and on reload(). Only the first
 * request after a change shows loading, so polling does not flash the table.
 * The latest fetcher is always used; `key` decides when to refetch.
 */
export function useQuery<R>(fetcher: (signal: AbortSignal) => Promise<R>, key: readonly unknown[], options: QueryOptions<R> = {}) {
  const { pollMs, errorFallback = '数据加载失败', enabled = true } = options;
  const [data, setData] = useState<R | undefined>(options.emptyValue);
  const [loading, setLoading] = useState(enabled);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const emptyRef = useRef(options.emptyValue);
  const keyString = JSON.stringify(key);
  const loadedFor = useRef('');
  useEffect(() => {
    if (!enabled) return;
    // A new key or reload() shows loading; a changed poll interval does not.
    const target = keyString + '#' + revision;
    if (loadedFor.current !== target) { loadedFor.current = target; setLoading(true); }
    return startQuery<R>({
      fetch: signal => fetcherRef.current(signal),
      onData: next => { setData(next); setError(null); },
      onError: message => { if (emptyRef.current !== undefined) setData(emptyRef.current); setError(message); },
      onSettled: () => setLoading(false),
      errorFallback,
      pollMs,
    });
  }, [keyString, revision, pollMs, enabled, errorFallback]);
  const reload = useCallback(() => setRevision(value => value + 1), []);
  return { data, setData, loading, error, reload };
}

/** Page and page size that return to page 1 whenever `resetKey` changes. */
export function usePageState(resetKey: unknown, initialPageSize = 15) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const keyString = JSON.stringify(resetKey);
  const previousKey = useRef(keyString);
  useEffect(() => {
    if (previousKey.current === keyString) return;
    previousKey.current = keyString;
    setPage(1);
  }, [keyString]);
  // antd pagination: a page-size change also returns to page 1.
  const onChange = useCallback((nextPage: number, nextSize: number) => {
    if (nextSize !== pageSize) { setPageSize(nextSize); setPage(1); } else setPage(nextPage);
  }, [pageSize]);
  return { page, pageSize, setPage, setPageSize, onChange };
}
