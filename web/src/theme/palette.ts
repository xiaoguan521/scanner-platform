// Design tokens for the "security operations" look (direction A). Dark is
// the default; the light set keeps the same structure for the theme toggle.
// Fonts are system stacks only: the platform runs on internal networks and
// must not fetch web fonts from the internet.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Tone = 'ok' | 'running' | 'warning' | 'error' | 'neutral';

export interface Palette {
  bgLayout: string;
  bgSider: string;
  bgContainer: string;
  bgElevated: string;
  bgSubtle: string;
  border: string;
  borderSubtle: string;
  text: string;
  textSecondary: string;
  textTertiary: string;
  primary: string;
  onPrimary: string;
  link: string;
  linkHover: string;
  success: string;
  warning: string;
  error: string;
  severity: Record<Severity, { fg: string; bg: string; solid: string }>;
  tone: Record<Tone, { fg: string; bg: string }>;
}

export const fontFamily = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Noto Sans SC', 'Microsoft YaHei', sans-serif";
export const monoFamily = "'JetBrains Mono', 'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace";

export const darkPalette: Palette = {
  bgLayout: '#0A0F1C',
  bgSider: '#0D1424',
  bgContainer: '#101827',
  bgElevated: '#162033',
  bgSubtle: '#0D1424',
  border: '#22304A',
  borderSubtle: '#1B2740',
  text: '#E6EDF7',
  textSecondary: '#9AA8BF',
  textTertiary: '#7C8BA5',
  primary: '#38BDF8',
  onPrimary: '#04121F',
  link: '#7DD3FC',
  linkHover: '#BAE6FD',
  success: '#34D399',
  warning: '#FB923C',
  error: '#FB7185',
  severity: {
    CRITICAL: { fg: '#FDA4AF', bg: 'rgba(251,113,133,0.14)', solid: '#FB7185' },
    HIGH: { fg: '#FDBA74', bg: 'rgba(251,146,60,0.14)', solid: '#FB923C' },
    MEDIUM: { fg: '#FDE68A', bg: 'rgba(250,204,21,0.12)', solid: '#FACC15' },
    LOW: { fg: '#93C5FD', bg: 'rgba(96,165,250,0.14)', solid: '#60A5FA' },
    INFO: { fg: '#CBD5E1', bg: 'rgba(148,163,184,0.14)', solid: '#94A3B8' },
  },
  tone: {
    ok: { fg: '#6EE7B7', bg: 'rgba(52,211,153,0.12)' },
    running: { fg: '#7DD3FC', bg: 'rgba(56,189,248,0.14)' },
    warning: { fg: '#FDBA74', bg: 'rgba(251,146,60,0.14)' },
    error: { fg: '#FDA4AF', bg: 'rgba(251,113,133,0.14)' },
    neutral: { fg: '#CBD5E1', bg: 'rgba(148,163,184,0.14)' },
  },
};

export const lightPalette: Palette = {
  bgLayout: '#F4F6F9',
  bgSider: '#FFFFFF',
  bgContainer: '#FFFFFF',
  bgElevated: '#FFFFFF',
  bgSubtle: '#F9FAFB',
  border: '#D0D5DD',
  borderSubtle: '#E4E7EC',
  text: '#101828',
  textSecondary: '#475467',
  textTertiary: '#667085',
  primary: '#0369A1',
  onPrimary: '#FFFFFF',
  link: '#0369A1',
  linkHover: '#075985',
  success: '#067647',
  warning: '#B54708',
  error: '#B42318',
  severity: {
    CRITICAL: { fg: '#A3153F', bg: '#FCE7EE', solid: '#C01048' },
    HIGH: { fg: '#A3410A', bg: '#FDEEE3', solid: '#E04F16' },
    MEDIUM: { fg: '#7A5600', bg: '#FBF3D5', solid: '#EAAA08' },
    LOW: { fg: '#1D4ED8', bg: '#E6EDFD', solid: '#2F5BEA' },
    INFO: { fg: '#475467', bg: '#EEF1F5', solid: '#98A2B3' },
  },
  tone: {
    ok: { fg: '#067647', bg: '#E3F7EC' },
    running: { fg: '#075985', bg: '#E0F2FE' },
    warning: { fg: '#A3410A', bg: '#FDEEE3' },
    error: { fg: '#A3153F', bg: '#FCE7EE' },
    neutral: { fg: '#475467', bg: '#EEF1F5' },
  },
};
