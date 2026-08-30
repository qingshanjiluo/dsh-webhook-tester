import React from 'react';

export const inject = ['settingsScope', 'slots', 'locale'] as const;

export function apply(ctx: any) {
  const { settingsScope, slots, locale } = ctx;

  locale.register('dsh-webhook-tester', {
    enabled: 'Enable Webhook Tester',
    port: 'Port',
    title: 'Webhook Tester',
    description: 'Receives and logs incoming HTTP webhooks for inspection.',
  });

  settingsScope.registerCard({
    pluginId: 'dsh-webhook-tester',
    title: () => locale.t('dsh-webhook-tester.title'),
    description: () => locale.t('dsh-webhook-tester.description'),
    component: WebhookCard,
  });
}

function WebhookCard(props: { settings: any; updateSettings: any }) {
  const { settings, updateSettings } = props;
  const t = (k: string) => k;

  const enabled = settings.get('enabled') ?? true;
  const port = settings.get('port') ?? 5678;

  return React.createElement(
    'div',
    { style: { display: 'flex', flexDirection: 'column', gap: '12px' } },
    React.createElement(
      'div',
      { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' } },
      React.createElement('label', null, t('dsh-webhook-tester.enabled')),
      React.createElement('input', {
        type: 'checkbox',
        checked: enabled,
        onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
          updateSettings('enabled', e.target.checked),
      })
    ),
    React.createElement(
      'div',
      { style: { display: 'flex', flexDirection: 'column', gap: '4px' } },
      React.createElement('label', null, t('dsh-webhook-tester.port')),
      React.createElement('input', {
        type: 'number',
        min: 1024,
        max: 65535,
        value: port,
        onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
          updateSettings('port', Number(e.target.value)),
        style: { width: '100px', padding: '4px 8px', borderRadius: '4px', border: '1px solid #ccc' },
      })
    )
  );
}
