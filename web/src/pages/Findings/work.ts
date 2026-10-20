// Notes are plain text; keep validation aligned with the Server's UTF-8 byte bound.
export function findingNoteInput(body: string): string {
  if (new TextEncoder().encode(body).length > 2000 || /[\p{Cc}\u2028\u2029]/u.test(body) || !body.trim()) {
    throw new Error('备注须为 1–2000 UTF-8 字节的纯文本，不能包含换行或控制字符');
  }
  return body.trim();
}
