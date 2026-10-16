import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AppLayout } from './components/Layout/AppLayout';
import { DashboardPage } from './pages/Dashboard';
import { AssetsPage } from './pages/Assets';
import { ScopesPage } from './pages/Scopes';
import { TasksPage } from './pages/Tasks';
import { FindingsPage } from './pages/Findings';
import { NodesPage } from './pages/Nodes';

export const App: React.FC = () => {
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
            <Route path="/nodes" element={<NodesPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AppLayout>
      </HashRouter>
    </ThemeProvider>
  );
};
