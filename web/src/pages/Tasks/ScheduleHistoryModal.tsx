import React, { useState } from 'react';
import { Alert, Button, Modal, Typography } from 'antd';
import { DataTable } from '../../components/DataState';
import { ScheduleStatusTag } from '../../components/Semantic';
import { useQuery } from '../../api/query';
import { fetchScheduleRuns } from '../../api/runtime';
import { formatTime } from '../../utils/time';
import type { Schedule, ScheduleRun } from '../../types';

/** Read-only run history of one schedule, 50 runs per page. */
export const ScheduleHistoryModal: React.FC<{ schedule: Schedule | null; onClose: () => void }> = ({ schedule, onClose }) => {
  const [page, setPage] = useState(1);
  const runs = useQuery(signal => fetchScheduleRuns(schedule?.id ?? '', page, signal), [schedule?.id, page], { enabled: Boolean(schedule), errorFallback: '历史运行记录加载失败' });
  const close = () => { setPage(1); onClose(); };
  return (
    <Modal title={`定时任务历史运行${schedule ? `：${schedule.name}` : ''}`} open={Boolean(schedule)} onCancel={close} footer={<Button onClick={close}>关闭</Button>} width={780}>
      {runs.error && <Alert type="error" showIcon message="历史运行记录加载失败" description={runs.error}/>}
      <DataTable<ScheduleRun> rowKey="id" loading={runs.loading} dataSource={runs.data?.items ?? []} locale={{ emptyText: '暂无运行记录' }} pagination={{ current: page, pageSize: 50, total: runs.data?.total ?? 0, hideOnSinglePage: true, showSizeChanger: false, onChange: setPage }} columns={[
        { title: '触发时间', dataIndex: 'triggeredAt', width: 190, render: (value: string) => formatTime(value) },
        { title: '状态', dataIndex: 'status', width: 150, render: (value: string) => <ScheduleStatusTag value={value}/> },
        { title: '任务 ID', dataIndex: 'taskId', width: 240, ellipsis: true, render: (value: string) => value || '—' },
        { title: '错误', dataIndex: 'error', ellipsis: true, render: (value: string) => value || '—' },
      ]}/>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>历史记录只展示触发时间、任务状态和任务标识；任务结果仍在扫描任务清册及漏洞页面查看。删除定时计划不会删除这份历史。</Typography.Paragraph>
    </Modal>
  );
};
