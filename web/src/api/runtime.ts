import { requestJSON } from './client';
import type { ScanTask, TaskInput, Schedule, Finding, FindingEvent, FindingAssignee, FindingNote, RuleJob, CustomRule, KnowledgeEntry } from '../types';

export const createTask = (input:TaskInput) => requestJSON<ScanTask>('/api/v1/tasks','POST',input);
export const cancelTask = (id:string) => requestJSON('/api/v1/tasks/'+encodeURIComponent(id)+'/cancel','POST');
export const archiveTask = (id:string) => requestJSON('/api/v1/tasks/'+encodeURIComponent(id)+'/archive','POST');
export const restoreTask = (id:string) => requestJSON('/api/v1/tasks/'+encodeURIComponent(id)+'/restore','POST');
export const deleteTask = (id:string) => requestJSON<{status:string}>('/api/v1/tasks/'+encodeURIComponent(id),'DELETE');
export const saveSchedule = (input: Omit<Schedule,'id'|'enabled'|'lastTaskId'|'lastError'|'createdBy'>) => requestJSON<Schedule>('/api/v1/schedules','POST',input);
export const updateSchedule = (id:string,input: Omit<Schedule,'id'|'enabled'|'lastTaskId'|'lastError'|'createdBy'>) => requestJSON<Schedule>('/api/v1/schedules/'+encodeURIComponent(id),'PUT',input);
export const deleteSchedule = (id:string) => requestJSON<{status:string}>('/api/v1/schedules/'+encodeURIComponent(id),'DELETE');
export const toggleSchedule = (id:string,enabled:boolean) => requestJSON('/api/v1/schedules/'+encodeURIComponent(id),'PATCH',{enabled});
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
