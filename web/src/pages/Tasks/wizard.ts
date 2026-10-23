export interface WizardValues {
  engine?: string;
  mode?: string;
  portPreset?: string;
  window?: boolean;
  opsApproved?: boolean;
}

export type ScanPlan = 'quick' | 'standard';
export interface ScanPlanDefaults {
  portPreset: 'common' | 'common-and-custom';
  intensity: 'gentle' | 'standard';
  portRanges: string;
  portExclusions: string;
  customRuleIds: string[];
}

export const scanPlanDefaults: Record<ScanPlan, ScanPlanDefaults> = {
  quick: { portPreset: 'common', intensity: 'gentle', portRanges: '', portExclusions: '', customRuleIds: [] },
  standard: { portPreset: 'common-and-custom', intensity: 'standard', portRanges: '', portExclusions: '', customRuleIds: [] },
};

export function getScanPlanDefaults(plan: string): ScanPlanDefaults {
  return scanPlanDefaults[plan as ScanPlan] ?? scanPlanDefaults.quick;
}

export function isAutoTaskWizard(values: WizardValues, editingSchedule: boolean): boolean {
  return values.engine === 'auto' && values.mode === 'now' && !editingSchedule;
}

export function wizardStepFields(step: number, values: WizardValues): string[] {
  if (step === 0) return ['assetIds'];
  if (step === 1) return ['portPreset', 'intensity', 'portExclusions', 'customRuleIds',
    ...(['custom', 'common-and-custom'].includes(values.portPreset ?? '') ? ['portRanges'] : [])];
  if (step === 2) return ['mode', 'window', ...(values.window ? ['weekdays', 'start', 'end', 'timeZone'] : [])];
  return ['opsApproved'];
}

export function assertTaskSubmission(values: WizardValues, canWrite: boolean, wizard: boolean, step: number): void {
  if (!canWrite) throw new Error('当前账号没有创建扫描任务的权限');
  if (wizard && step !== 3) throw new Error('请完成向导并在确认页创建任务');
  if ((values.engine === 'auto' || values.engine === 'port-probe') && !values.opsApproved) {
    throw new Error('请确认运维授权和四层转发排除情况');
  }
}
