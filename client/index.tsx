import React from 'react';
import { createSettingsCard } from '@deepseek-ai/dsh-settings';

export default createSettingsCard({
  title: 'webhook-tester',
  description: 'Webhook 测试器',
  config: [
    { key: 'enabled', type: 'boolean', label: '启用插件', default: true },
    { key: 'port', type: 'number', label: '监听端口', default: 5678 },
    { key: 'maxLogs', type: 'number', label: '最大日志数', default: 100 },
  ],
});
