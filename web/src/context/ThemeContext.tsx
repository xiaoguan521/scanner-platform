import React, { createContext, useContext, useEffect, useState } from 'react';
import { ConfigProvider, theme as antdTheme } from 'antd';
import { darkPalette, fontFamily, lightPalette, type Palette } from '../theme/palette';

interface ThemeContextType {
  isDark: boolean;
  palette: Palette;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType>({
  isDark: true,
  palette: darkPalette,
  toggleTheme: () => {},
});

export const useAppTheme = () => useContext(ThemeContext);

function readSavedTheme(): boolean {
  try {
    const saved = localStorage.getItem('app_theme');
    return saved !== null ? saved === 'dark' : true;
  } catch {
    return true;
  }
}

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isDark, setIsDark] = useState<boolean>(readSavedTheme);
  const palette = isDark ? darkPalette : lightPalette;

  const toggleTheme = () => {
    setIsDark((prev) => {
      const next = !prev;
      try { localStorage.setItem('app_theme', next ? 'dark' : 'light'); } catch { /* theme stays for this session */ }
      return next;
    });
  };

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.style.colorScheme = isDark ? 'dark' : 'light';
    document.body.style.backgroundColor = palette.bgLayout;
    document.body.style.color = palette.text;
  }, [isDark, palette]);

  return (
    <ThemeContext.Provider value={{ isDark, palette, toggleTheme }}>
      <ConfigProvider
        theme={{
          algorithm: isDark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
          token: {
            colorPrimary: palette.primary,
            colorInfo: palette.primary,
            colorSuccess: palette.success,
            colorWarning: palette.warning,
            colorError: palette.error,
            colorLink: palette.link,
            colorLinkHover: palette.linkHover,
            colorTextLightSolid: palette.onPrimary,
            colorBgLayout: palette.bgLayout,
            colorBgContainer: palette.bgContainer,
            colorBgElevated: palette.bgElevated,
            colorBorder: palette.border,
            colorBorderSecondary: palette.borderSubtle,
            colorText: palette.text,
            colorTextSecondary: palette.textSecondary,
            colorTextTertiary: palette.textTertiary,
            borderRadius: 8,
            borderRadiusLG: 12,
            fontFamily,
            fontSize: 14,
          },
          components: {
            // Tooltips and popovers sit on a dark spotlight surface in both
            // themes, so they keep light text even though primary uses dark text.
            Tooltip: { colorTextLightSolid: '#F8FAFC' },
            Table: {
              headerBg: palette.bgSubtle,
              headerColor: palette.textTertiary,
              rowHoverBg: isDark ? '#131E33' : '#F5F8FF',
              borderColor: palette.borderSubtle,
              cellPaddingBlock: 12,
            },
            Card: { headerFontSize: 15 },
            Menu: {
              itemBg: 'transparent',
              subMenuItemBg: 'transparent',
              itemSelectedBg: palette.bgElevated,
              itemSelectedColor: palette.text,
              itemColor: palette.textSecondary,
              itemHoverColor: palette.text,
              itemHoverBg: palette.bgElevated,
              groupTitleColor: palette.textTertiary,
            },
            Layout: { siderBg: palette.bgSider, headerBg: palette.bgLayout, bodyBg: palette.bgLayout, triggerBg: palette.bgSider, triggerColor: palette.textSecondary },
          },
        }}
      >
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  );
};
