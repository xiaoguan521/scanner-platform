export function canAcceptRisk(status:string) { return ['OPEN','REOPENED','IN_PROGRESS'].includes(status); }
export function acceptanceInput(reason:string,until:string,now=Date.now()):{reason:string;acceptedUntil:string} {
 const trimmed=reason.trim();
 if (new TextEncoder().encode(trimmed).length<1 || new TextEncoder().encode(trimmed).length>500 || /[\p{Cc}]/u.test(trimmed)) throw new Error('接受原因需为 1–500 UTF-8 字节，不能包含控制字符');
 const parsed=Date.parse(until);
 if (!Number.isFinite(parsed) || parsed<=now || parsed>now+365*24*60*60*1000) throw new Error('到期时间必须在未来 365 天内');
 return {reason:trimmed,acceptedUntil:new Date(parsed).toISOString()};
}
