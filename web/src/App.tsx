import React, { Suspense, lazy } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AppLayout } from './components/Layout/AppLayout';
import { AuthProvider, useAuth } from './auth/AuthProvider';
import { LoadingSkeleton } from './components/Semantic';

// Each page is its own chunk so the first screen loads only what it shows.
const DashboardPage = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.DashboardPage })));
const AssetsPage = lazy(() => import('./pages/Assets').then(m => ({ default: m.AssetsPage })));
const BusinessGroupsPage = lazy(() => import('./pages/BusinessGroups').then(m => ({ default: m.BusinessGroupsPage })));
const AssetImportHistoryPage = lazy(() => import('./pages/AssetImportHistory').then(m => ({ default: m.AssetImportHistoryPage })));
const ScopesPage = lazy(() => import('./pages/Scopes').then(m => ({ default: m.ScopesPage })));
const TasksPage = lazy(() => import('./pages/Tasks').then(m => ({ default: m.TasksPage })));
const FindingsPage = lazy(() => import('./pages/Findings').then(m => ({ default: m.FindingsPage })));
const KnowledgePage = lazy(() => import('./pages/Knowledge').then(m => ({ default: m.KnowledgePage })));
const NodesPage = lazy(() => import('./pages/Nodes').then(m => ({ default: m.NodesPage })));
const UsersPage = lazy(() => import('./pages/Users').then(m => ({ default: m.UsersPage })));
const AuditPage = lazy(() => import('./pages/Audit').then(m => ({ default: m.AuditPage })));
const ReportsPage = lazy(() => import('./pages/Reports').then(m => ({ default: m.ReportsPage })));
const SettingsPage = lazy(() => import('./pages/Settings').then(m => ({ default: m.SettingsPage })));
const NotificationsPage = lazy(() => import('./pages/Notifications').then(m => ({ default: m.NotificationsPage })));

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
