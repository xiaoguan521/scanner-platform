import React, { Suspense, lazy } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AppLayout } from './components/Layout/AppLayout';
import { AuthProvider, useAuth } from './auth/AuthProvider';
import { LoadingSkeleton } from './components/Semantic';

// Each page is its own chunk so the first screen loads only what it shows.
// A tab left open across a release asks for chunk names that no longer exist;
// reload once to pick up the new build instead of showing a blank page.
const reloadFlag = 'page-chunk-reload';
function lazyPage<T extends React.ComponentType>(load: () => Promise<T>) {
  return lazy(async () => {
    try {
      const page = await load();
      try { sessionStorage.removeItem(reloadFlag); } catch { /* storage unavailable */ }
      return { default: page };
    } catch (cause) {
      let reloaded = true;
      try { reloaded = sessionStorage.getItem(reloadFlag) === '1'; if (!reloaded) sessionStorage.setItem(reloadFlag, '1'); } catch { /* storage unavailable */ }
      if (!reloaded) { window.location.reload(); return new Promise<never>(() => {}); }
      throw cause;
    }
  });
}
const DashboardPage = lazyPage(() => import('./pages/Dashboard').then(m => m.DashboardPage));
const AssetsPage = lazyPage(() => import('./pages/Assets').then(m => m.AssetsPage));
const BusinessGroupsPage = lazyPage(() => import('./pages/BusinessGroups').then(m => m.BusinessGroupsPage));
const AssetImportHistoryPage = lazyPage(() => import('./pages/AssetImportHistory').then(m => m.AssetImportHistoryPage));
const ScopesPage = lazyPage(() => import('./pages/Scopes').then(m => m.ScopesPage));
const TasksPage = lazyPage(() => import('./pages/Tasks').then(m => m.TasksPage));
const FindingsPage = lazyPage(() => import('./pages/Findings').then(m => m.FindingsPage));
const KnowledgePage = lazyPage(() => import('./pages/Knowledge').then(m => m.KnowledgePage));
const NodesPage = lazyPage(() => import('./pages/Nodes').then(m => m.NodesPage));
const UsersPage = lazyPage(() => import('./pages/Users').then(m => m.UsersPage));
const AuditPage = lazyPage(() => import('./pages/Audit').then(m => m.AuditPage));
const ReportsPage = lazyPage(() => import('./pages/Reports').then(m => m.ReportsPage));
const SettingsPage = lazyPage(() => import('./pages/Settings').then(m => m.SettingsPage));
const NotificationsPage = lazyPage(() => import('./pages/Notifications').then(m => m.NotificationsPage));

const AuthenticatedRoutes: React.FC = () => {
  const {user} = useAuth();
  return (
    <ThemeProvider>
      <HashRouter>
        <AppLayout>
          <Suspense fallback={<LoadingSkeleton rows={6} label="正在加载页面…" />}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/business-groups" element={<BusinessGroupsPage />} />
            <Route path="/asset-import-history" element={<AssetImportHistoryPage />} />
            <Route path="/scopes" element={<ScopesPage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/knowledge" element={<KnowledgePage />} />
            <Route path="/nodes" element={<NodesPage />} />
            <Route path="/users" element={user?.role === "admin" ? <UsersPage /> : <Navigate to="/" replace />} />
            <Route path="/audit" element={user?.role === "admin" ? <AuditPage /> : <Navigate to="/" replace />} />
            <Route path="/settings" element={user?.role === "admin" ? <SettingsPage /> : <Navigate to="/" replace />} />
            <Route path="/notifications" element={<NotificationsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </Suspense>
        </AppLayout>
      </HashRouter>
    </ThemeProvider>
  );
};
export const App: React.FC = () => <AuthProvider><AuthenticatedRoutes /></AuthProvider>;
