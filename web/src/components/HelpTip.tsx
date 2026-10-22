import React from 'react';
import { Button, Popover, Space } from 'antd';
import { QuestionCircleOutlined } from '@ant-design/icons';
import type { ReactNode } from 'react';

// Rule and policy explanations live behind a help icon instead of permanent
// page banners; errors and destructive-action warnings stay inline.
export const HelpTip: React.FC<{ title: string; children: ReactNode }> = ({ title, children }) => (
  <Popover title={title} content={<div style={{ maxWidth: 380, whiteSpace: 'normal' }}>{children}</div>} trigger={['hover', 'click']}>
    <Button type="text" size="small" aria-label={`说明：${title}`} icon={<QuestionCircleOutlined />} />
  </Popover>
);

export const TitleWithHelp: React.FC<{ title: ReactNode; helpTitle: string; help: ReactNode }> = ({ title, helpTitle, help }) => (
  <Space size={2}>{title}<HelpTip title={helpTitle}>{help}</HelpTip></Space>
);
