import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AppLayout } from './components/Layout/AppLayout';
import { DashboardPage } from './pages/Dashboard';
import { AssetsPage } from './pages/Assets';
import { ScopesPage } from './pages/Scopes';
import { TasksPage } from './pages/Tasks';
import { FindingsPage } from './pages/Findings';
import { KnowledgePage } from './pages/Knowledge';
import { NodesPage } from './pages/Nodes';
import { UsersPage } from './pages/Users';
import { AuditPage } from './pages/Audit';
import { ReportsPage } from './pages/Reports';
import { AuthProvider, useAuth } from './auth/AuthProvider';

const AuthenticatedRoutes: React.FC = () => {
  const {user} = useAuth();
  return (
    <ThemeProvider>
      <HashRouter>
        <AppLayout>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/scopes" element={<ScopesPage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/knowledge" element={<KnowledgePage />} />
            <Route path="/nodes" element={<NodesPage />} />
            <Route path="/users" element={user?.role === "admin" ? <UsersPage /> : <Navigate to="/" replace />} />
            <Route path="/audit" element={user?.role === "admin" ? <AuditPage /> : <Navigate to="/" replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AppLayout>
      </HashRouter>
    </ThemeProvider>
  );
};
export const App: React.FC = () => <AuthProvider><AuthenticatedRoutes /></AuthProvider>;
