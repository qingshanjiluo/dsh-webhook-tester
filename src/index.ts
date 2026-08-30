/**
 * dsh-webhook-tester — Webhook测试器
 *
 * 功能：
 * 1. Webhook接收
 * 2. Webhook重放
 * 3. 日志管理
 *
 * 工具：webhook_start, webhook_stop, webhook_list, webhook_replay, webhook_inspect, webhook_clear
 * 命令：/webhook
 * 配置：enabled, port
 */
import { z } from 'zod';
import http from 'node:http';
import { randomUUID } from 'node:crypto';

const configSchema = z.object({
  enabled: z.boolean().default(true),
  port: z.number().int().min(1024).max(65535).default(5678),
  maxLogs: z.number().int().min(1).max(10000).default(100),
});

interface Webhook {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: unknown;
  receivedAt: string;
  source: string;
}

let server: http.Server | null = null;
let webhooks: Webhook[] = [];
const MAX_BODY_SIZE = 1024 * 1024; // 1MB limit
let maxLogs = 100;

function startServer(port: number): string {
  if (server) {
    stopServer();
  }

  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '请求体超过 1MB 限制' }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (totalSize > MAX_BODY_SIZE) return;
      const bodyRaw = Buffer.concat(chunks).toString('utf-8');
      let body: unknown;
      try {
        body = JSON.parse(bodyRaw);
      } catch {
        body = bodyRaw;
      }

      const webhook: Webhook = {
        id: randomUUID(),
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: req.headers as Record<string, string>,
        body,
        receivedAt: new Date().toISOString(),
        source: req.socket.remoteAddress ?? 'unknown',
      };

      webhooks.push(webhook);
      if (webhooks.length > maxLogs) {
        webhooks = webhooks.slice(-maxLogs);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, id: webhook.id }));
    });
  });

  server.on('error', (err: Error) => {
    console.error(`[dsh-webhook-tester] 服务器错误: ${err.message}`);
    server = null;
  });

  server.listen(port);
  return `http://localhost:${port}`;
}

function stopServer(): void {
  if (server) {
    server.close();
    server = null;
  }
}

function getReceivedWebhooks(): Webhook[] {
  return [...webhooks];
}

function clearWebhooks(): void {
  webhooks = [];
}

function replayWebhook(id: string, targetUrl: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const wh = webhooks.find((w) => w.id === id);
    if (!wh) {
      return reject(new Error(`Webhook ${id} not found`));
    }

    const url = new URL(targetUrl);
    const bodyStr = typeof wh.body === 'string' ? wh.body : JSON.stringify(wh.body);

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: wh.method,
        headers: wh.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf-8'),
          });
        });
      }
    );

    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

function generateCurlCommand(webhook: Webhook): string {
  const parts = ['curl', `-X ${webhook.method}`];
  for (const [key, value] of Object.entries(webhook.headers)) {
    parts.push(`-H '${key}: ${value}'`);
  }
  const bodyStr = typeof webhook.body === 'string' ? webhook.body : JSON.stringify(webhook.body);
  if (bodyStr) {
    parts.push(`-d '${bodyStr}'`);
  }
  parts.push(`'REPLACE_WITH_URL'`);
  return parts.join(' ');
}

export function apply(ctx: any, config?: Config) {
  const cfg = config || configSchema.parse({});
  maxLogs = cfg.maxLogs;

  if (cfg.enabled && cfg.port) {
    startServer(cfg.port);
  }

  ctx.tools.register({
    name: 'webhook_start',
    description: '启动 Webhook 接收服务器',
    parameters: z.object({ port: z.number().int().min(1024).max(65535).optional() }),
    async execute(params: { port?: number }) {
      const p = params.port ?? cfg.port;
      const url = startServer(p);
      return { server_url: url, message: `Webhook 接收器已启动: ${url}` };
    },
  });

  ctx.tools.register({
    name: 'webhook_stop',
    description: '停止 Webhook 接收服务器',
    parameters: z.object({}),
    async execute() {
      stopServer();
      return { message: 'Webhook 接收器已停止' };
    },
  });

  ctx.tools.register({
    name: 'webhook_list',
    description: '列出所有接收到的 Webhook',
    parameters: z.object({}),
    async execute() {
      return { webhooks: getReceivedWebhooks(), count: webhooks.length };
    },
  });

  ctx.tools.register({
    name: 'webhook_replay',
    description: '重放 Webhook 到目标 URL',
    parameters: z.object({ id: z.string(), target_url: z.string().url() }),
    async execute(params: { id: string; target_url: string }) {
      const result = await replayWebhook(params.id, params.target_url);
      return { status: result.status, body: result.body };
    },
  });

  ctx.tools.register({
    name: 'webhook_inspect',
    description: '查看 Webhook 详细信息',
    parameters: z.object({ id: z.string() }),
    async execute(params: { id: string }) {
      const wh = webhooks.find(w => w.id === params.id);
      if (!wh) return { error: `Webhook ${params.id} 不存在` };
      return { webhook: wh, curl: generateCurlCommand(wh) };
    },
  });

  ctx.tools.register({
    name: 'webhook_clear',
    description: '清空所有 Webhook 记录',
    parameters: z.object({}),
    async execute() {
      clearWebhooks();
      return { message: '所有 Webhook 已清空' };
    },
  });

  ctx.commands.register({
    name: 'webhook',
    description: 'Webhook 测试',
    async execute(args: string) {
      const parts = args.trim().split(/\s+/);
      const action = parts[0] || 'list';
      if (action === 'start') {
        const p = parts[1] ? Number(parts[1]) : cfg.port;
        const url = startServer(p);
        return { content: `Webhook 接收器已启动: ${url}` };
      }
      if (action === 'stop') { stopServer(); return { content: '已停止' }; }
      if (action === 'list') {
        const list = getReceivedWebhooks();
        return { content: list.length === 0 ? '暂无记录' : list.map(w => `${w.id} ${w.method} ${w.url}`).join('\n') };
      }
      if (action === 'clear') { clearWebhooks(); return { content: '已清空' }; }
      return { content: '用法: /webhook start|stop|list|clear [port]' };
    },
  });

  ctx.settings.register({ title: 'webhook-tester', description: 'Webhook 测试器', config: configSchema });
}
