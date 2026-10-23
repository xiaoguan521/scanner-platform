// Every time in the UI is shown in the platform time zone from system
// settings, so operators in different places read the same clock.
let displayTimeZone: string | undefined;
const formatters = new Map<string, Intl.DateTimeFormat>();

function formatter(timeZone: string | undefined, withSeconds: boolean): Intl.DateTimeFormat {
  const key = `${timeZone ?? ''}|${withSeconds}`;
  let cached = formatters.get(key);
  if (!cached) {
    cached = new Intl.DateTimeFormat('zh-CN', {
      timeZone, hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', ...(withSeconds ? { second: '2-digit' } : {}),
    });
    formatters.set(key, cached);
  }
  return cached;
}

/** Sets the zone used by formatTime; an unknown zone falls back to the browser's. */
export function setDisplayTimeZone(timeZone?: string): void {
  if (!timeZone) { displayTimeZone = undefined; return; }
  try { formatter(timeZone, true); displayTimeZone = timeZone; } catch { displayTimeZone = undefined; }
}

export function getDisplayTimeZone(): string | undefined {
  return displayTimeZone;
}

/** "2026/10/23 09:30:00" in the platform time zone; empty or invalid values give the fallback. */
export function formatTime(value?: string | number | Date | null, fallback = '—', options: { seconds?: boolean } = {}): string {
  if (value === undefined || value === null || value === '') return fallback;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return formatter(displayTimeZone, options.seconds ?? true).format(date);
}

/** "2026/10/23" in the platform time zone. */
export function formatDate(value?: string | number | Date | null, fallback = '—'): string {
  const text = formatTime(value, '', { seconds: false });
  return text ? text.split(' ')[0] : fallback;
}
