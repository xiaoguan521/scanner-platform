import React, { useEffect, useRef, useState } from 'react';
import { Drawer, message } from 'antd';
import { errorMessage } from '../../api/client';
import { pollIntervals, pollWhileVisible } from '../../api/polling';
import { exportTask, fetchTask, fetchTaskLogs } from '../../api/runtime';
import { isTerminalTask } from './phases';
import { TaskDetail } from './TaskDetail';
import { renderTaskProgress } from './TaskProgress';
import type { ScanTask, TaskLog } from '../../types';

// The parent owns the open task so row actions (pause, resume) can patch it;
// the drawer loads the full record and logs, and polls while it is running.
export const TaskDetailDrawer: React.FC<{
  task: ScanTask | null;
  onTaskChange: (task: ScanTask) => void;
  onClose: () => void;
  canWrite: boolean;
  onPause: (task: ScanTask) => void;
  onResume: (task: ScanTask) => void;
  onStop: (id: string) => void;
}> = ({ task, onTaskChange, onClose, canWrite, onPause, onResume, onStop }) => {
  const [logs, setLogs] = useState<TaskLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [exporting, setExporting] = useState<'json' | 'csv' | null>(null);
  const loadedId = useRef('');
  const onTaskChangeRef = useRef(onTaskChange);
  onTaskChangeRef.current = onTaskChange;
  // Running tasks refresh every 3 seconds while the detail is open; finished ones load once.
  const detailTerminal = task ? isTerminalTask(task.status) : true;
  useEffect(() => {
    if (!task) return;
    const id = task.id;
    const controller = new AbortController(); let inFlight = false;
    const load = () => {
      if (inFlight) return;
      inFlight = true;
      const initial = loadedId.current !== id;
      if (initial) { setLoading(true); setError(''); setLogs([]); } else setRefreshing(true);
      Promise.all([fetchTask(id, controller.signal), fetchTaskLogs(id, controller.signal)]).then(([next, nextLogs]) => {
        if (!controller.signal.aborted) { loadedId.current = id; onTaskChangeRef.current(next); setLogs(nextLogs.items); setError(''); }
      }).catch(cause => { if (!controller.signal.aborted) setError(errorMessage(cause, '任务详情加载失败')); }).finally(() => { inFlight = false; if (!controller.signal.aborted) { setLoading(false); setRefreshing(false); } });
    };
    load();
    const stopPolling = detailTerminal ? undefined : pollWhileVisible(load, pollIntervals.activeTask);
    return () => { controller.abort(); stopPolling?.(); };
  }, [task?.id, detailTerminal]);
  const download = async (format: 'json' | 'csv') => {
    if (!task) return;
    setExporting(format);
    try {
      const blob = await exportTask(task.id, format);
      const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `task-result.${format}`; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
      message.success(`任务结果已导出为 ${format.toUpperCase()}`);
    } catch (cause) { message.error(errorMessage(cause, '任务结果导出失败')); } finally { setExporting(null); }
  };
  return (
    <Drawer title={task ? `任务详情：${task.id}` : '任务详情'} open={Boolean(task)} width="min(1040px, 100vw)" onClose={() => { loadedId.current = ''; onClose(); }} destroyOnClose>
      {task && <TaskDetail task={task} logs={logs} loading={loading} refreshing={refreshing} error={error} canWrite={canWrite} exporting={exporting} progress={renderTaskProgress(task)}
        onPause={() => onPause(task)} onResume={() => onResume(task)} onStop={() => onStop(task.id)} onExport={format => void download(format)}/>}
    </Drawer>
  );
};
