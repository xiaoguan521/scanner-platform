import { requestBlob, requestJSON } from './client';
import type { ScanPlan, ScanPlanInput, ScanTask, TaskInput, Schedule, ScheduleRun, Finding, FindingEvent, FindingAssignee, FindingNote, FindingRetest, RuleJob, CustomRule, KnowledgeEntry, TaskLog } from '../types';

export const createTask = (input:TaskInput) => requestJSON<ScanTask>('/api/v1/tasks','POST',input);
export const createScanPlan = (input:ScanPlanInput) => requestJSON<ScanPlan>('/api/v1/scan-plans','POST',input);
export const updateScanPlan = (id:string,input:ScanPlanInput) => requestJSON<ScanPlan>('/api/v1/scan-plans/'+encodeURIComponent(id),'PUT',input);
export const deleteScanPlan = (id:string) => requestJSON<{status:string}>('/api/v1/scan-plans/'+encodeURIComponent(id),'DELETE');
export const cancelTask = (id:string) => requestJSON('/api/v1/tasks/'+encodeURIComponent(id)+'/cancel','POST');
export const pauseTask = (id:string) => requestJSON<{status:'PAUSED'}>('/api/v1/tasks/'+encodeURIComponent(id)+'/pause','POST');
export const resumeTask = (id:string) => requestJSON<{status:'PENDING'}>('/api/v1/tasks/'+encodeURIComponent(id)+'/resume','POST');
export const archiveTask = (id:string) => requestJSON('/api/v1/tasks/'+encodeURIComponent(id)+'/archive','POST');
export const restoreTask = (id:string) => requestJSON('/api/v1/tasks/'+encodeURIComponent(id)+'/restore','POST');
export const deleteTask = (id:string) => requestJSON<{status:string}>('/api/v1/tasks/'+encodeURIComponent(id),'DELETE');
export const fetchTask = (id:string, signal?:AbortSignal) => requestJSON<ScanTask>('/api/v1/tasks/'+encodeURIComponent(id),'GET',undefined,signal);
export const fetchTaskLogs = (id:string, signal?:AbortSignal) => requestJSON<{items:TaskLog[];total:number}>('/api/v1/tasks/'+encodeURIComponent(id)+'/logs','GET',undefined,signal);
export const exportTask = (id:string, format:'json'|'csv', signal?:AbortSignal) => requestBlob('/api/v1/tasks/'+encodeURIComponent(id)+'/export?format='+format, signal, format==='csv'?'text/csv':'application/json');
export const saveSchedule = (input: Omit<Schedule,'id'|'enabled'|'lastTaskId'|'lastError'|'createdBy'>) => requestJSON<Schedule>('/api/v1/schedules','POST',input);
export const updateSchedule = (id:string,input: Omit<Schedule,'id'|'enabled'|'lastTaskId'|'lastError'|'createdBy'>) => requestJSON<Schedule>('/api/v1/schedules/'+encodeURIComponent(id),'PUT',input);
export const deleteSchedule = (id:string) => requestJSON<{status:string}>('/api/v1/schedules/'+encodeURIComponent(id),'DELETE');
export const toggleSchedule = (id:string,enabled:boolean) => requestJSON('/api/v1/schedules/'+encodeURIComponent(id),'PATCH',{enabled});
export const fetchScheduleRuns = (id:string,page=1,signal?:AbortSignal) => requestJSON<{items:ScheduleRun[];total:number}>('/api/v1/schedules/'+encodeURIComponent(id)+'/runs?limit=50&offset='+Math.max(0,page-1)*50,'GET',undefined,signal);
export const updateFinding = (id:string,status:string,acceptance?:{reason:string;acceptedUntil:string}) => requestJSON<Finding>('/api/v1/findings/'+encodeURIComponent(id),'PATCH',{status,...acceptance});
export const batchFindingDisposition = (items:{id:string;expectedStatus:string}[],status:string,acceptance?:{reason:string;acceptedUntil:string}) => requestJSON<{updated:number;items:Finding[]}>('/api/v1/findings/batch-disposition','POST',{items,status,...acceptance});
export const fetchFindingEvents = (id:string,signal?:AbortSignal) => requestJSON<{items:FindingEvent[];total:number}>('/api/v1/findings/'+encodeURIComponent(id)+'/events','GET',undefined,signal);
export const createCustomRule = (input:Omit<CustomRule,'template'>) => requestJSON<CustomRule>('/api/v1/custom-rules','POST',input);
export const updateCustomRule = (id:string,input:Omit<CustomRule,'template'>) => requestJSON<CustomRule>('/api/v1/custom-rules/'+encodeURIComponent(id),'PUT',input);
export const deleteCustomRule = (id:string) => requestJSON<{status:string}>('/api/v1/custom-rules/'+encodeURIComponent(id),'DELETE');
export const fetchRules = (url:string,expectedSha256:string) => requestJSON<RuleJob>('/api/v1/rules/fetch','POST',{url,expectedSha256});
export const activateRules = (version:string,rollback:boolean) => requestJSON<RuleJob>('/api/v1/rules/'+encodeURIComponent(version)+'/activate','POST',{rollback});
export async function importRules(file:File):Promise<RuleJob> {
  if(file.size>256*1024*1024) throw new Error('ZIP 大小不能超过 256 MiB');
  const body=new FormData(); body.append('bundle',file);
  const response=await fetch('/api/v1/rules/import',{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'},credentials:'same-origin',body});
  if(!response.ok) throw new Error('上传失败，请检查登录状态、权限及 ZIP 大小');
  return response.json() as Promise<RuleJob>;
}

export const createKnowledge = (input:KnowledgeEntry) => requestJSON<KnowledgeEntry>('/api/v1/knowledge','POST',input);
export const updateKnowledge = (id:string,input:KnowledgeEntry) => requestJSON<KnowledgeEntry>('/api/v1/knowledge/'+encodeURIComponent(id),'PUT',input);
export const deleteKnowledge = (id:string) => requestJSON('/api/v1/knowledge/'+encodeURIComponent(id),'DELETE');
export const importKnowledge = (items:KnowledgeEntry[]) => requestJSON<{imported:number}>('/api/v1/knowledge/import','POST',{items});

export const fetchFindingAssignees = (signal?:AbortSignal) => requestJSON<{items:FindingAssignee[];total:number}>('/api/v1/findings/assignees','GET',undefined,signal);
export const assignFinding = (id:string,assigneeId:string) => requestJSON<Finding>('/api/v1/findings/'+encodeURIComponent(id)+'/assignee','PUT',{assigneeId});
export const fetchFindingNotes = (id:string,signal?:AbortSignal) => requestJSON<{items:FindingNote[];total:number}>('/api/v1/findings/'+encodeURIComponent(id)+'/notes','GET',undefined,signal);
export const addFindingNote = (id:string,body:string) => requestJSON<FindingNote>('/api/v1/findings/'+encodeURIComponent(id)+'/notes','POST',{body});
export const createFindingRetest = (id:string) => requestJSON<{task:ScanTask;retest:FindingRetest}>('/api/v1/findings/'+encodeURIComponent(id)+'/retest','POST',{});
export const fetchFindingRetests = (id:string,signal?:AbortSignal) => requestJSON<{items:FindingRetest[];total:number}>('/api/v1/findings/'+encodeURIComponent(id)+'/retests','GET',undefined,signal);
