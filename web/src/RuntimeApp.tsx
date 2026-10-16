import React from 'react';
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AppLayout } from './components/Layout/AppLayout';
import { DashboardPage } from './pages/Dashboard';
import { AssetsPage } from './pages/Assets';
import { TasksPage } from './pages/Tasks';
import { FindingsPage } from './pages/Findings';
import { ScopesPage } from './pages/Scopes';
import { NodesPage } from './pages/Nodes';

// The explicitly local runtime reuses existing pages. The separate account UI
// remains available with the existing --dev-ui entrypoint.
export const RuntimeApp: React.FC = () => (
  <ThemeProvider>
    <HashRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/scopes" element={<ScopesPage />} />
          <Route path="/nodes" element={<NodesPage />} />
          <Route path="*" element={<Navigate to="/tasks" replace />} />
        </Routes>
      </AppLayout>
    </HashRouter>
  </ThemeProvider>
);
