import React from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { useAppTheme } from '../context/ThemeContext';

/** Page title row: title, one-line context and the page's primary actions. */
export const PageHeader: React.FC<{ title: ReactNode; description?: ReactNode; extra?: ReactNode }> = ({ title, description, extra }) => {
  const { palette } = useAppTheme();
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, color: palette.text }}>{title}</h1>
        {description && <span style={{ fontSize: 13, color: palette.textSecondary }}>{description}</span>}
      </div>
      {extra && <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>{extra}</div>}
    </div>
  );
};

/** Bordered surface with an optional title row; `flush` removes body padding for tables and lists. */
export const Panel: React.FC<{ title?: ReactNode; extra?: ReactNode; flush?: boolean; children: ReactNode; style?: CSSProperties; 'aria-label'?: string }> = ({ title, extra, flush, children, style, ...rest }) => {
  const { palette } = useAppTheme();
  return (
    <section aria-label={rest['aria-label']} style={{ borderRadius: 12, background: palette.bgContainer, border: `1px solid ${palette.borderSubtle}`, overflow: 'hidden', minWidth: 0, ...style }}>
      {(title || extra) && (
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '16px 20px', ...(flush ? {} : { paddingBottom: 0 }) }}>
          {title && <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: palette.text }}>{title}</h2>}
          {extra && <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>{extra}</div>}
        </div>
      )}
      <div style={flush ? undefined : { padding: 20 }}>{children}</div>
    </section>
  );
};

/** Responsive auto-fit grid for metric tiles and panels. */
export const AutoGrid: React.FC<{ min: number; gap?: number; children: ReactNode }> = ({ min, gap = 16, children }) => (
  <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fit, minmax(min(${min}px, 100%), 1fr))`, gap }}>{children}</div>
);
