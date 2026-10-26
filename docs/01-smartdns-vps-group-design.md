# SmartDNS 节点列表专用直连组 (passwall_vps) 架构设计

## 一、 现状与痛点

在 PassWall 原生架构中，当 DNS 分流选择 SmartDNS 时：
- sing-box/xray 内部将所有节点域名（`vpslist`）路由至直连 DNS 端口 `127.0.0.1:15354`；
- PassWall 将该端口直接套用绑定在普通的国内分组（`smartdns_local_group`，默认 `cn`）；
- `cn` 组内通常配置了中国移动/电信/联通等本地 ISP 的明文 UDP DNS 服务器，以及面向国内大厂网页测速的规则。

### 存在的核心缺陷
1. **控制面与数据面混淆**：节点域名在每次建链、探测时均以明文 UDP 广播给运营商 ISP，带来泄露与审计风险；
2. **GTM / CDN GeoDNS 调度偏差**：ISP 递归查询境外节点域名时极易返回已被阻断或限速的特定 IP 段（如 `152.175.44.0/24`）；
3. **测速干扰**：SmartDNS 全局开启的 80/443 测速对纯代理高位端口节点无效，引发不必要延迟。

---

## 二、 架构目标：单进程内四组（Group）多租户完全解耦

**核心纪律：保持单一 SmartDNS 守护进程，绝不起第二进程。**
完全依托 SmartDNS 原生 Group 命名空间能力，在同一实例内划分出第四个平行的独立组。

```text
┌─────────────────────────────────────────────────────────────────┐
│ SmartDNS 单一守护进程 (PID: 4679 / smartdns.conf)                │
│                                                                 │
│  [Group: cn]              : 监听 :6053                          │
│                            普通国内上网（含 ISP DNS、测速）        │
│                                                                 │
│  [Group: passwall_default]: 监听 :15355                         │
│                            局域网分流中枢（内网 Hosts + chnlist） │
│                                                                 │
│  [Group: passwall_proxy]  : 纯上游逻辑组 (无监听端口)              │
│                            上游 -> 127.0.0.1:15356 (sing-box)   │
│                                                                 │
│  [Group: passwall_vps]    : 监听 127.0.0.1:15354@lo             │
│  (★ 新增独立组)            上游 -> 阿里/字节 DoH 直连             │
│                            专供 sing-box/xray 节点列表解析       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 三、 SmartDNS 源码级缓存分桶隔离机制实证

经审阅 SmartDNS Release 48.4 底层 C 源码，确认 **Group 分割天然自带缓存物理隔离**，无需借助 `-no-cache`。

### 1. 缓存结构体定义 (`src/include/smartdns/dns_cache.h:113`)
```c
struct dns_cache_key {
	const char *domain;
	dns_type_t qtype;
	const char *dns_group_name;   // 组名原生作为 Cache Key 的组成部分
	uint32_t query_flag;
};
```

### 2. 缓存比对硬过滤 (`src/dns_cache.c:266`)
```c
hash_table_for_each_possible(dns_cache_head.cache_hash, dns_cache, node, key)
{
	if (dns_cache->info.qtype != cache_key->qtype) {
		continue;
	}
	if (strncasecmp(cache_key->domain, dns_cache->info.domain, DNS_MAX_CNAME_LEN) != 0) {
		continue;
	}
	// 组名不一致，直接跳过！
	if (strncmp(cache_key->dns_group_name, dns_cache->info.dns_group_name, DNS_GROUP_NAME_LEN) != 0) {
		continue;
	}
    ...
```

### 结论
- `passwall_vps` 中缓存的记录带有该组专属标识；
- 局域网普通设备访问 `:6053` 或 `:15355` 时，由于 `cache_key->dns_group_name` 不匹配，**物理上绝不可能命中该组缓存**；
- 缓存双向隔离，节点记录不串味至普通上网流量，普通污染记录也不干扰节点建链。保留组内正常缓存可避免每次重连都产生网络 DoH 开销。

---

## 四、 纯净加密 DoH 上游选型

放弃存在跨网限速和偶发 TLS reset 的腾讯 `doh.pub`，选用三网 Anycast 且支持直接 IP 访问的顶级加密上游（**免除 Bootstrap 自解析死锁**）：

| 服务商 | SmartDNS 配置 | 说明 |
|---|---|---|
| **阿里云公共 DNS** | `server-https https://223.5.5.5/dns-query -host-name dns.alidns.com` | 国内三网 BGP，稳定度最高，直连 IP 访问 |
| **字节火山引擎 (TrafficRoute)** | `server-https https://180.184.1.1/dns-query -host-name doh.volcengine.com` | 字节自建 Anycast，对中国移动网络 peer 极优，无频控 |

---

## 五、 最终落地的 SmartDNS 配置文件形态 (`/tmp/etc/smartdns/passwall.conf`)

```text
# ------------------ 节点列表专属直连组 (同进程 Group 隔离) ------------------
# 1. 仅限回环端口绑定
bind [::]:15354@lo -group passwall_vps -no-rule-addr
bind-tcp [::]:15354@lo -group passwall_vps -no-rule-addr

# 2. 纯净加密 DoH (阿里 + 字节火山引擎，免 Bootstrap 解析)
server-https https://223.5.5.5/dns-query -host-name dns.alidns.com -group passwall_vps -exclude-default-group
server-https https://180.184.1.1/dns-query -host-name doh.volcengine.com -group passwall_vps -exclude-default-group

# 3. 隔离作用域：不继承全局规则，禁用测速与双栈等待，屏蔽 HTTPS/65 查询
group-begin passwall_vps -inherit none
force-qtype-SOA 65
domain-rules /./ -nameserver passwall_vps -speed-check-mode none -d no
group-end
# -------------------------------------------------------------------------
```

---

## 六、 侵入性与兼容性结论

- **内核与防火墙（nftables/iptables）**：0 改动；
- **核心客户端（sing-box/xray）**：0 改动（原本直连即定向至 `:15354`）；
- **改动面**：仅限于 SmartDNS 配置渲染器（`helper_smartdns_add*.lua`）在开启该模式时将 `:15354` 的绑定目标从 `LOCAL_GROUP` 替换为 `passwall_vps`。
