# dsh-webhook-tester

> DeepSeek Harness Webhook 测试器

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ 功能特性

- 🌐 **Webhook 接收**: 本地 HTTP 服务器接收 webhook
- 🔄 **重放功能**: 将收到的 webhook 重放到目标 URL
- 📋 **日志管理**: 查看、检查、清除收到的 webhook

## 📦 安装

```bash
npm install dsh-webhook-tester
```

## 🛠️ 工具

| 工具名 | 描述 | 参数 |
|--------|------|------|
| `webhook_start` | 启动接收服务器 | 无 |
| `webhook_stop` | 停止服务器 | 无 |
| `webhook_list` | 列出收到的 webhook | 无 |
| `webhook_replay` | 重放 webhook | `id`, `target_url` |
| `webhook_inspect` | 检查 webhook 详情 | `id` |
| `webhook_clear` | 清除所有 webhook | 无 |

## 📋 命令

- `/webhook start` — 启动服务器
- `/webhook stop` — 停止
- `/webhook list` — 列出
- `/webhook clear` — 清除

## ⚙️ 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | boolean | `true` | 启用插件 |
| `port` | number | `5678` | 监听端口 |
| `maxLogs` | number | `100` | 最大日志数 |

## 📄 License

MIT
