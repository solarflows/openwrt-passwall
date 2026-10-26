# sing-box URLTest 组选择锁死机制与单点假象深度复盘

- 设备：`czw.lan` (ImmortalWrt / IPQ807x / NSS-EDMA，内核 6.18.55)
- sing-box 核心版本：`1.14.3` (go1.27.1 linux/arm64)
- 现象特征：突发“所有代理节点不通”，直连网络正常，一段时间后自愈或重启恢复。

---

## 一、 根本机理：sing-box 1.14.3 URLTest 选择锁死 (Latch)

经查证 sing-box 源码 `protocol/group/urltest.go` 与 `common/urltest/urltest.go`：

### 1. `DialContext` 无连接级 Failover
```go
func (s *URLTest) DialContext(...) (net.Conn, error) {
    outbound = s.group.selectedOutboundTCP   // 直接使用缓存的 selectedOutboundTCP
    conn, err := outbound.DialContext(ctx, network, destination)
    if err == nil { return ... }
    s.logger.ErrorContext(ctx, err)          // 记 ERROR
    s.group.history.DeleteURLTestHistory(outbound.Tag()) // 仅删除该成员 history
    return nil, err                          // 不做 fallback，直接向上层抛错
}
```

### 2. `Select` 忽略无 history 成员，全灭时触发锁死
```go
func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
    ...
    for _, detour := range g.outbounds {
        history := g.history.LoadURLTestHistory(RealTag(g.outbound, detour))
        if history == nil { continue } // 探测失败的成员直接被跳过
        if minDelay == 0 || minDelay > history.Delay+g.tolerance {
            minDelay = history.Delay
            minOutbound = detour
        }
    }
    if minOutbound == nil {
        return g.members[0], false    // 兜底返回第一成员，但 exists = false
    }
    return minOutbound, true
}

func (g *URLTestGroup) performUpdateCheck() {
    if outbound, exists := g.Select(N.NetworkTCP); outbound != nil &&
       (g.selectedOutboundTCP == nil || (exists && outbound != g.selectedOutboundTCP)) {
        g.selectedOutboundTCP = outbound
    }
}
```
**锁死成因**：当一个组内的所有成员在某轮探测中全部失败，`Select` 无法选出任何候选者，返回 `exists = false`。`performUpdateCheck` 中的条件为假，**`selectedOutboundTCP` 原地不动，整组被锁死在上一轮选中的死节点上**。

---

## 二、 日志的“单一供应商 (yuyan) 集中”假象剖析

在 PassWall 默认的 `log.level = "info"` 下：
1. **探测失败不记录**：sing-box 仅以 `Debug` 级别输出 `outbound <tag> unavailable: <err>`，在 info 级别下完全隐形；
2. **只有被选中的成员报错**：`DialContext` 在处理用户流量时报错才会记录 `ERROR`。

因为雨燕云（yuyan）节点为 BGP 优化，正常时延迟最低，因此日常恒定作为 `selectedOutboundTCP`。当整组全灭时，所有报错集中落在当前选中的 yuyan 节点上，**形成了“只有 yuyan 挂了”的视觉假象**。

---

## 三、 影子实例实证：非 yuyan 节点“长期全灭”真相

我们在路由现场剥离 `inbounds` 并开启 `debug` 与 Clash API 启动了影子实例进行独立探测。以香港组（`urltest-FIfwOnZe`，26 个成员）为例：

### 探测结果对比表

| 分类 | 数量 | 成员特征 | 探测结果 | 失败底层根因 (Debug 日志实测) |
|---|---|---|---|---|
| **yuyan 节点** | 10 | BGP 优化 | **10 全部通过** (525~838ms) | - |
| **非 yuyan 节点** | 16 | 多供应商/专线/自建 | **16 全部失败** (`history` 恒空) | 详见下文 |

### 非 yuyan 成员失败根因清单（非事件偶发，属长期配置缺陷）
1. **自签证书校验阻断 (`x509: unknown authority`)**：
   - 节点：`香港ic`, `香港nb1`, `香港065`, `香港ev`, `香港HKT动态` 等；
   - 根因：服务端配置了 SNI 伪装（如 `server_name: bing.com`），但服务端使用了自签证书且客户端未开启 `tls_allowInsecure`。
2. **私有 DoH 上游失效阻断**：
   - 节点：`香港 MPLS 专线1/2` (`req-hfsdfsf-33.93451forest.cn`)；
   - 根因：订阅自带的私有 DoH `38.207.164.191:8080` 自身无法连通（i/o timeout），导致该域名根本无法解析。
3. **HTTP 握手异常 (`Head ... 204: EOF`)**：
   - 节点：`dadw25158` 旗下所有节点；
   - 根因：TCP 握手成功但无法到达探测目标。
4. **端口直接拒绝 (`connect: connection refused`)**：
   - 节点：`202.81.229.97:2083` 等。

### 实证结论
**这三个主要 URLTest 组在功能上实质等价于“单供应商组”**。由于非 yuyan 节点长期不可用，一旦 yuyan 自身因 GTM 波动或网段阻断，整组立即陷入零可用状态并触发锁死。

---

## 四、 根治与加固清单

1. **修复证书缺陷**：对自签证书节点开启 `tls_allowInsecure`，直接盘活 5 个以上备用节点；
2. **剔除/修复失效私有 DoH**：替换 `38.207.164.191:8080`，恢复专线解析；
3. **主流量切至真正具备冗余的分组**：如 `ipv6boy` 组（73 成员，无 yuyan 依赖，多供应商大面积健康）；
4. **实施 SmartDNS `passwall_vps` 专属直连组**：切断节点域名向移动 ISP 的明文泄漏与 GTM GeoDNS 调度失真。
