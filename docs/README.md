# PassWall 自研架构与底层机理研究文档 (Docs)

本目录记录当前自研 Fork 仓针对 PassWall、SmartDNS 以及 sing-box / Xray 核心的架构改造、底层机制复盘与深度研究档案。

---

## 目录索引

| 文件 | 主题 | 核心内容与机制 |
|---|---|---|
| [`01-smartdns-vps-group-design.md`](./01-smartdns-vps-group-design.md) | **SmartDNS 节点列表专用直连组架构设计** | 单进程 4-Group 多租户模型、源码级缓存分桶隔离证明、纯净加密 DoH 选型与 UI 规划 |
| [`02-singbox-urltest-incident-postmortem.md`](./02-singbox-urltest-incident-postmortem.md) | **sing-box URLTest 组锁死机制与单点假象深度复盘** | `protocol/group/urltest.go` 源码推导、日志选择假象、影子实例实测非 yuyan 节点全死真相 |

---

## 文件存储规范

1. **设计文档与复盘报告**：一律以标准 Markdown 提交至版本库，供团队与多端设备持久化共享；
2. **原始诊断数据**：任何包含敏感节点 IP、端口、密码、订阅 Token 的原始日志（`*.log`、`*.tgz`、`*.json`）一律放入 `docs/raw/` 或忽略后缀，严禁推送到远程仓库。
