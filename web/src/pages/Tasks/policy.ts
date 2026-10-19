import type { PortProbeRange } from '../../types';
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
