import React, { createContext, useContext, useEffect, useState } from 'react';
import { theme, ConfigProvider, theme as antdTheme } from 'antd';

interface ThemeContextType {
  isDark: boolean;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType>({
  isDark: true,
  toggleTheme: () => {},
});

export const useAppTheme = () => useContext(ThemeContext);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem('app_theme');
    return saved !== null ? saved === 'dark' : true; // 默认深色科技风
  });

  const toggleTheme = () => {
    setIsDark((prev) => {
      const next = !prev;
      localStorage.setItem('app_theme', next ? 'dark' : 'light');
      return next;
    });
  };

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
      document.body.style.backgroundColor = '#0b0f19';
      document.body.style.color = '#e2e8f0';
    } else {
      document.documentElement.classList.remove('dark');
      document.body.style.backgroundColor = '#f8fafc';
      document.body.style.color = '#1e293b';
    }
  }, [isDark]);

  return (
    <ThemeContext.Provider value={{ isDark, toggleTheme }}>
      <ConfigProvider
        theme={{
          algorithm: isDark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
          token: {
            colorPrimary: '#1677ff',
            colorSuccess: '#13c2c2',
            colorWarning: '#fa8c16',
            colorError: '#ff4d4f',
            colorInfo: '#1677ff',
            borderRadius: 6,
            fontFamily:
              "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', sans-serif",
            ...(isDark
              ? {
                  colorBgContainer: '#131b2e',
                  colorBgElevated: '#1b253b',
                  colorBgLayout: '#0b0f19',
                  colorBorder: '#23304c',
                  colorBorderSecondary: '#1d2840',
                }
              : {
                  colorBgContainer: '#ffffff',
                  colorBgElevated: '#ffffff',
                  colorBgLayout: '#f1f5f9',
                }),
          },
        }}
      >
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  );
};
