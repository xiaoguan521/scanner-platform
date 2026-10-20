import type { Asset, PortProbeConfig, PortProbeRange, ScanPolicy } from '../../types';
export function parsePortRanges(text?:string):PortProbeRange[]{
  if(!text?.trim()) return [];
  const parts=text.split(',').map(value=>value.trim());
  if(parts.length>128) throw new Error('端口范围最多填写 128 段');
  return parts.map(part=>{
    const match=/^([0-9]{1,5})(?:-([0-9]{1,5}))?$/.exec(part);
    if(!match) throw new Error('端口请填写数字或起止范围，如 8080, 9000-9010');
    const start=Number(match[1]),end=Number(match[2]??match[1]);
    if(start<1||end>65535||start>end) throw new Error('端口范围必须为 1–65535，且起始端口不大于结束端口');
    return {start,end};
  });
}
export function showRanges(ranges?:PortProbeRange[]):string{return ranges?.map(range=>range.start===range.end?String(range.start):`${range.start}-${range.end}`).join(', ')||'无';}
export function coversAllPorts(ranges:PortProbeRange[]): boolean { const sorted=[...ranges].sort((a,b)=>a.start-b.start); let next=1; for(const r of sorted){ if(r.start>next)return false; next=Math.max(next,r.end+1); } return next>65535; }
export const presetLabels:Record<string,string>={common:'常见端口',custom:'自定义范围','common-and-custom':'常见端口 + 自定义范围',registered:'已登记端口',full:'全端口（1–65535）'};
export function compressPorts(ports?:number[]): string {
  const sorted=[...new Set(ports??[])].sort((a,b)=>a-b);const ranges:PortProbeRange[]=[];
  for(const port of sorted){const last=ranges[ranges.length-1];if(last&&port===last.end+1)last.end=port;else ranges.push({start:port,end:port});}
  return ranges.length?showRanges(ranges):'';
}
export function summarizePorts(ports?:number[]): string { const text=compressPorts(ports);return text.length>180?`${text.slice(0,180)}…（共 ${new Set(ports).size} 个端口）`:text||'无'; }
export function expandPortRanges(text?:string):number[] {return [...new Set(parsePortRanges(text).flatMap(r=>Array.from({length:r.end-r.start+1},(_,i)=>r.start+i)))].sort((a,b)=>a-b);}

// Preview uses the same registered-port sources and exclusions as Server.
// Server still validates and freezes the current policy when creating the task.
export function previewProbePorts(asset: Asset, config: PortProbeConfig, policy: ScanPolicy): {requested: number[]; effective: number[]} {
  const selected=new Set<number>();
  const addRanges=(ranges:PortProbeRange[])=>{for(const range of ranges)for(let port=range.start;port<=range.end;port++)selected.add(port);};
  if(config.preset==='full')addRanges([{start:1,end:65535}]);
  if(config.preset==='common'||config.preset==='common-and-custom')for(const port of policy.commonPorts)selected.add(port);
  if(config.preset==='custom'||config.preset==='common-and-custom')addRanges(config.ranges??[]);
  if(config.preset==='registered'){
    for(const port of asset.ports??[])if(port.kind!=='EXCLUDED_PROXY')selected.add(port.port);
    for(const service of asset.services??[])selected.add(service.port);
  }
  const requested=[...selected].sort((a,b)=>a-b);
  const excluded=new Set([...(asset.quarantinedPorts??[]),...(asset.ports??[]).filter(port=>port.kind==='EXCLUDED_PROXY').map(port=>port.port)]);
  const ranges=[...policy.exclusions,...(config.exclusions??[])];
  return {requested,effective:requested.filter(port=>!excluded.has(port)&&!ranges.some(range=>port>=range.start&&port<=range.end))};
}
