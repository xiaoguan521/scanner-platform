import type { FindingRetest } from '../../types';

const activeStatuses = new Set(['PENDING','WAITING_WINDOW','RUNNING','PAUSED_WINDOW']);

export const retestIsActive = (item:FindingRetest) => activeStatuses.has(item.status);
export const retestStatusLabel = (status:string) => ({
  PENDING:'待执行', WAITING_WINDOW:'等待时间窗', RUNNING:'执行中', PAUSED_WINDOW:'时间窗暂停',
  COMPLETED:'已完成', FAILED:'失败', CANCELED:'已取消',
}[status] ?? status);
