import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { RuntimeApp } from './RuntimeApp';
import { isDemoMode } from './api/client';

async function start() {
  let localRuntime = false;
  if (!isDemoMode) {
    try {
      const response = await fetch('/api/v1/system/capabilities', { cache: 'no-store' });
      if (response.ok) {
        const body = await response.json() as { enabled?: string[] };
        localRuntime = body.enabled?.includes('synthetic-worker') === true;
      }
    } catch { /* The normal app displays unavailable state. */ }
  }
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>{localRuntime ? <RuntimeApp /> : <App />}</React.StrictMode>
  );
}
void start();
