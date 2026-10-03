# V2Ray VPN 内置订阅机制逆向分析与 sub-proxy 中继服务

> 从 APK 逆向到 Clash/Mihomo 可用配置的完整研究过程

## 目录

1. [背景与目标](#1-背景与目标)
2. [APK 逆向：提取订阅加密密钥](#2-apk-逆向提取订阅加密密钥)
3. [sub-proxy：订阅中继代理](#3-sub-proxy订阅中继代理)
4. [httpupgrade 传输层兼容——核心难题](#4-httpupgrade-传输层兼容核心难题)
5. [节点可用性排查：url-test 与 gstatic](#5-节点可用性排查url-test-与-gstatic)
6. [DNS 存活过滤与地理位置重命名](#6-dns-存活过滤与地理位置重命名)
7. [路由规则设计](#7-路由规则设计)
8. [V2Ray 路由 domain 匹配规则](#8-v2ray-路由-domain-匹配规则)
9. [NAS 部署（QNAP）](#9-nas-部署qnap)
10. [UA 协商：一个订阅地址适配所有客户端](#10-ua-协商一个订阅地址适配所有客户端)
11. [踩坑记录](#11-踩坑记录)
12. [文件清单](#12-文件清单)

---

## 1. 背景与目标

某款安卓 VPN 应用（V2Ray VPN 6.5.0）内置了一个"订阅"功能，用户无需填写任何服务器信息即可一键连接海外节点。该订阅的数据源是互联网上公开的 **fanqiang（翻墙）** 镜像列表，经过加密后内置在 APK 中，客户端启动时解密并拉取。

**目标**：将这个内置订阅的节点提取出来，转换成 **Clash Meta（Mihomo）** 可用的 YAML 配置文件，让路由器、软路由、NAS 等设备也能自动获取和更新节点。

---

## 2. APK 逆向：提取订阅加密密钥

### 2.1 获取 APK

APK 通过 FTP 拉取：`ftp://192.168.31.74:1234/V2rayVPN_6.5.0.apk`

文件信息：
- 大小：17,214,320 字节
- SHA256：`2FC899349A5A6DCDA662EEF1B6C8E6866BB8B153EB0E12E69F95756CD1AE19CB`

### 2.2 解包与反编译

使用工具：
- APK 解压（ZIP 格式）
- jadx 反编译 DEX 字节码 → Java 源码

### 2.3 发现的核心参数

从反编译代码中找到以下关键常量：

| 参数 | 值 | 说明 |
|------|-----|------|
| AES-256-CBC Key | `36KeAARKZuKF39N9LFyycLUyKMhZDq0B` | 32 字节密钥 |
| AES-256-CBC IV | `36KeAARKZuKF39N9` | 16 字节 IV（前 16 字节同 Key） |
| 请求 UA | `NekoBox/Android/6.5.0 (Prefer ClashMeta Format)` | 伪装成 NekoBox 客户端 |

### 2.4 镜像源列表

APK 内置了多个镜像源，按地区分为 **CN（中国）** 和 **EN（国际）** 两组：

**CN 节点：**
```
https://gitlab.com/bobmolen/cloud/raw/master/vsp-cn.py
https://bannedbook.github.io/fanqiang/vsp-cn.py
https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-cn.py
https://storage.googleapis.com/jwnews/vsp-cn.py
```

**EN 节点：**
```
https://bannedbook.github.io/fanqiang/vsp-en.py
https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-en.py
https://gitlab.com/bobmolen/cloud/raw/master/vsp-en.py
https://storage.googleapis.com/jwnews/vsp-en.py
```

- 文件扩展名 `.py` 是伪装，实际内容是 **Base64 + AES-256-CBC 加密**的密文
- 解密后是 `vmess://` 格式的节点列表（每行一个链接）
- 每个镜像源的加密数据可能不同（时效性差异），按顺序重试直到成功

### 2.5 加密/解密算法

```
Ciphertext = Base64(AES-256-CBC(raw, key=KEY, iv=IV))
Padding = PKCS7
```

解密伪代码：
```python
ct = base64.b64decode(ciphertext)
pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)
# 去除 PKCS7 padding
pad = pt[-1]
if 1 <= pad <= 16:
    pt = pt[:-pad]
plaintext = pt.decode('utf-8')
```

---

## 3. sub-proxy：订阅中继代理

### 3.1 架构

```
┌─────────────────────────────────────────────────────────┐
│                      NAS / 路由器                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              sub-proxy (port 60088)              │    │
│  │  ┌───────────┐  ┌──────────┐  ┌─────────────┐  │    │
│  │  │ 定时拉取    │  │ AES 解密  │  │ 格式转换     │  │    │
│  │  │ (每15分钟)  │→ │ + 节点重  │→ │ Clash YAML   │  │    │
│  │  │ 多个镜像源  │  │ 命名/过滤 │  │ / vmess raw │  │    │
│  │  └───────────┘  └──────────┘  └─────────────┘  │    │
│  └─────────────────────────────────────────────────┘    │
│                          ↓                               │
│            http://<NAS_IP>:60088/clash                   │
└─────────────────────────────────────────────────────────┘
                           ↓
              ┌────────────┼────────────┐
              ↓            ↓            ↓
          Clash/Mihomo  v2rayNG  NekoBox/Shadowrocket
           (自动YAML)   (vmess)      (vmess)
```

### 3.2 核心功能

| 功能 | 说明 |
|------|------|
| **定时刷新** | 每 15 分钟从所有镜像源拉取，解密后合并去重 |
| **节点地理位置重命名** | 自动 DNS 解析节点域名 → 查 IP 归属地 → 重命名为 "美国·San Francisco·节点名" |
| **DNS 存活过滤** | 通过 JSON DoH（Google/AliDNS/Cloudflare）验证域名 A 记录，剔除死域名 |
| **磁盘持久化** | 刷新成功后写入 `last_good.txt`，重启服务立即恢复，不依赖网络 |
| **Format auto-negotiation** | 根据请求 User-Agent 自动选择 YAML（Clash 系）或原始 vmess 格式 |
| **Token 鉴权** | 访问需要 `?token=` 参数或 `Authorization: Bearer` 头，防止未授权访问 |
| **健康检查端点** | `/healthz` 无需 token，返回 JSON 状态（节点数、错误信息等） |

### 3.3 API 端点

| 路径 | 鉴权 | 返回格式 | 说明 |
|------|------|----------|------|
| `/` | token | 按 UA 自动选择 | 合并 CN+EN 节点 |
| `/cn` | token | 按 UA 自动选择 | 仅 CN 节点 |
| `/en` | token | 按 UA 自动选择 | 仅 EN 节点 |
| `/clash` | token | Mihomo YAML | 合并节点，强制 YAML |
| `/clash/cn` | token | Mihomo YAML | CN 节点，强制 YAML |
| `/clash/en` | token | Mihomo YAML | EN 节点，强制 YAML |
| `/clash-ip/...` | token | Mihomo YAML | 同上但 IP 直连（实验性） |
| `/healthz` | 无需 | JSON | 健康检查 |

### 3.4 订阅地址示例

```
# Clash/Mihomo 客户端直接填入此 URL：
http://<NAS_IP>:60088/clash?token=<YOUR_TOKEN>

# 或者不带 /clash，让服务端根据 UA 自动选择格式：
http://<NAS_IP>:60088/?token=<YOUR_TOKEN>
```

---

## 4. httpupgrade 传输层兼容——核心难题

### 4.1 问题发现

原始订阅的所有节点都使用 **V2Ray httpupgrade 传输层**，而非常见的 WebSocket：

```json
{
  "add": "fr1a-20260812xxx.85888880.xyz",
  "port": 80,
  "id": "c97cf46e-1554-36cb-8b36-c3556b883dc4",
  "net": "httpupgrade",
  "path": "/windows11",
  "tls": "",
  "scy": "auto",
  "aid": 0
}
```

### 4.2 Clash/Mihomo 不直接支持 httpupgrade

查阅 **MetaCubeX/Mihomo 官方文档**（transport.md）发现：

- Mihomo 的有效 `network` 枚举值为：`http` / `h2` / `grpc` / `ws` / `mkcp` / `mekya` / `xhttp`
- **不存在 `httpupgrade` 这个 network 值**

### 4.3 解决方案：ws + v2ray-http-upgrade

Mihomo 在 `ws-opts` 中提供了两个关键字段（transport.md 第 280-286 行）：

```yaml
ws-opts:
  path: /windows11
  v2ray-http-upgrade: true          # 使用 HTTP Upgrade 握手替代标准 WebSocket
  v2ray-http-upgrade-fast-open: false  # 等待服务器 101 响应后再发数据
```

**映射逻辑：**

| V2Ray vmess 字段 | Mihomo YAML 字段 | 说明 |
|------------------|-----------------|------|
| `net=httpupgrade` | `network: ws` + `v2ray-http-upgrade: true` | 核心映射 |
| 无 fastOpen 参数 | `v2ray-http-upgrade-fast-open: false` | 默认 false，匹配 v2ray 默认行为 |
| `path=/windows11` | `ws-opts.path: /windows11` | 路径保持不变 |
| `host=""` | 不设置 headers.Host（除非需要） | 空 host 表示不发送额外 Host 头 |

### 4.4 踩坑：fast-open 参数

**初次设定 `fast-open: true`** → 节点从 3/8 可用降到 2/8 可用。

原因：V2Ray 服务端默认 `fastOpen=false`，当客户端启用 fast-open 时，mihomo 在收到 101 响应前就发送了 vmess 数据，如果服务端不支持 fast-open，连接就会异常断开。

**最终设定 `fast-open: false`** → 恢复到 3/8 可用状态。这 3 个节点（us1a/us5a/us6a）能正常工作证明 httpupgrade 映射本身是正确的。

---

## 5. 节点可用性排查：url-test 与 gstatic

### 5.1 现象

配置部署后，Clash/Mihomo 客户端显示：
- ✅ **3 个节点正常工作**（us1a/us5a/us6a），延迟 300-333ms
- ❌ **5 个节点 url-test 失败**，报错 `Head https://www.gstatic.com/generate_204 failed`

### 5.2 逐步排查

| 步骤 | 检查项 | 结果 | 结论 |
|------|--------|------|------|
| 1 | DNS 解析 | 8 个域名全部解析到 Cloudflare IP | ✅ 域名存活 |
| 2 | HTTP 连接 | 8 个节点 TCP 80 全部可达 | ✅ 网络层正常 |
| 3 | HTTP 101 Upgrade | 所有 8 个节点返回 101 响应 + Server: cloudflare | ✅ Upgrade 握手成功 |
| 4 | v2rayNG/NekoBox 测试 | 8 个节点全部可用 | ✅ 协议层正常 |
| 5 | 响应头对比（正常 vs 失败） | 完全一致的 CF-RAY/Server/Upgrade 头 | ✅ 无服务端差异 |

**结论**：TCP 连通性正常、HTTP 101 Upgrade 握手正常、v2ray 系客户端全部可用——问题不在传输层，而在于 **Clash url-test 使用 gstatic.com 作为测试目标**，某些节点通过 CF 边缘无法访问 gstatic.com。

### 5.3 根因与修复

| 修复 | 效果 |
|------|------|
| 测试 URL 从 `https://www.gstatic.com/generate_204` 改为 `http://www.google.com` | **8/8 全部通过** ✅ |

**确认**：Shadowrocket 也是 CONNECT 超时但 TCP ping 正常，进一步证明是测试目标的问题，不是代理隧道的问题。

**最终 url-test 配置：**
```yaml
proxy-groups:
  - name: "AUTO"
    type: url-test
    url: "http://www.google.com"
    interval: 300
    tolerance: 50
```

---

## 6. DNS 存活过滤与地理位置重命名

### 6.1 DNS 存活过滤

**动机**：v2ray.vpn 的镜像源可能包含已失效的域名（解析不到 A 记录），这种节点在任何客户端都无法使用，应在服务端过滤掉。

**实现**：
- 通过多个 JSON DoH 提供商（dns.google、223.5.5.5、1.1.1.1）查询 A 记录
- 任意一个提供商返回 A 记录 → 判定为存活
- 所有提供商都无结果 → 判定为死域名，从列表中移除
- **安全阀**：先用 `baidu.com` 做控制探测，若控制探测也失败（DoH 不可达），则跳过过滤，保留所有节点

**当前状态**：所有 `*.85888880.xyz` 域名均解析到 Cloudflare（`172.67.140.40` / `104.21.70.226`），过滤正确保留。

### 6.2 地理位置重命名

**实现**：
1. 从 `vmess://` 链接的 `add` 字段提取域名
2. DNS 解析域名 → IPv4
3. 查询 `ipwho.is`（免费，无需 API Key）获取 IP 归属地
4. 重命名为 `国家·城市·原始名称`（如 `美国·San Francisco·us1a-20260812add.85888880.xyz`）

**IP/地理缓存**：
- IP → 位置缓存是 **持久化**的（IP 归属地基本不变）
- 域名 → IP 缓存是 **每刷新周期重置**（CDN 域名 IP 可能轮转）

---

## 7. 路由规则设计

### 7.1 规则结构（330+ 条）

```
优先级从高到低：
1. 私有/回环 IP        → DIRECT (no-resolve)
2. 广告/追踪器域名      → REJECT
3. Apple 推送/服务       → AUTO (代理)
4. 中国国内网站/服务     → DIRECT
5. .cn 后缀 / -cn 关键词 → DIRECT
6. 国际服务/Google/CDN   → AUTO (代理)
7. Telegram IP 段       → AUTO (no-resolve)
8. GEOIP,CN            → DIRECT
9. MATCH               → AUTO
```

### 7.2 规则分类

| 分类 | 数量 | 示例 |
|------|------|------|
| 私有 IP | 13 | `127.0.0.0/8`, `192.168.0.0/16`, `10.0.0.0/8` |
| 广告追踪 | 27 | `doubleclick.net`, `appsflyer.com`, `umeng` |
| Apple 服务 | 11 | `testflight.apple.com`, `apple-dns.net` |
| 国内直连 | 110+ | `qq.com`, `weixin.qq.com`, `bilibili.com`, `jd.com` |
| .cn 后缀 | 1 | `DOMAIN-SUFFIX,cn` |
| 国际代理 | 150+ | `google.com`, `youtube`, `facebook`, `openai`, CDN |
| Telegram | 10 | `91.108.4.0/22` 等 IP 段 |

### 7.3 规则集演进（踩坑记录）

**尝试 1**：使用 Mihomo `rule-providers` 从 jsDelivr CDN 动态拉取 Loyalsoldier/clash-rules

→ **失败**：Clash/Mihomo Android 客户端（clashmi）**不支持 rule-provider 的外部下载功能**，必须将规则硬编码在 YAML 中。

**尝试 2**：服务端直接拉取规则文件，内联写入 YAML

→ **失败**：所有规则文件合并后约 **14MB / 334K 行**，clashmi 无法加载如此大的配置文件。

**最终方案**：精选 **330+ 条硬编码规则**，覆盖日常使用场景，体积仅 16KB。

---

## 8. V2Ray 路由 domain 匹配规则

在 V2Ray 的路由配置中，`domain` 匹配规则有特殊的行为：

### 8.1 子域名自动匹配

```
domain:douyin.com
```

这 **自动匹配** 以下所有域名：
- `douyin.com`
- `www.douyin.com`
- `live.douyin.com`
- `a.b.c.douyin.com`
- 任何 `*.douyin.com` 子域名

### 8.2 错误写法

```
domain:*.douyin.com   ← 错误！
```

V2Ray 会把 `*` 当作字面量，试图匹配一个叫 `*.douyin.com` 的域名（不存在），等同于规则失效。

### 8.3 精确匹配

```
domain:aistudio.xiaomimimo.com
```

这只匹配这一个完整子域名，不会匹配 `xxx.aistudio.xiaomimimo.com`。

---

## 9. NAS 部署（QNAP）

### 9.1 环境

| 项目 | 值 |
|------|-----|
| NAS 型号 | QNAP |
| 部署路径 | `/vol1/1000/9/sub-proxy/` |
| 服务端口 | 60088 |

### 9.2 systemd 服务

服务文件 `sub-proxy.service`：

```ini
[Unit]
Description=V2Ray built-in subscription relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/vol1/1000/9/sub-proxy
ExecStart=/usr/bin/python3 /vol1/1000/9/sub-proxy/sub_proxy.py
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### 9.3 管理命令

```bash
# 部署更新
python ssh_exec.py put local/sub_proxy.py /tmp/sub_proxy.py
python ssh_exec.py exec cp /tmp/sub_proxy.py /vol1/1000/9/sub-proxy/sub_proxy.py
python ssh_exec.py exec systemctl restart sub-proxy

# 查看日志
python ssh_exec.py exec journalctl -u sub-proxy -f

# 验证
curl "http://<NAS_IP>:60088/healthz"
curl -s "http://<NAS_IP>:60088/clash?token=..." | head -30
```

---

## 10. UA 协商：一个订阅地址适配所有客户端

### 10.1 设计

服务端根据请求的 `User-Agent` 自动判断客户端类型，返回对应格式：

| User-Agent 含 | 返回格式 | 典型客户端 |
|--------------|----------|-----------|
| `clash` / `mihomo` / `cfi` / `hiddify` / `streisand` / `stagger` / `flclash` / `clashy` | Mihomo YAML | Clash Meta, Clash for Android, FlClash |
| 其他 | 原始 vmess:// 链接 | v2rayNG, NekoBox, SagerNet, Shadowrocket |

也可以通过路径强制格式：
- `/clash` → 强制 YAML
- `/cn` / `/en` → 强制 raw vmess

### 10.2 SubConverter 兼容

实现方式兼容 SubConverter 的 UA 协商：同一个订阅 URL 填入不同客户端时自动"适配"。

---

## 11. 踩坑记录

| # | 问题 | 原因 | 解决 |
|---|------|------|------|
| 1 | Clash 所有节点超时 | `network: ws` 缺少 `v2ray-http-upgrade: true`，Mihomo 用标准 WebSocket 握手而服务端期望 httpupgrade | 添加 `v2ray-http-upgrade: true` |
| 2 | 5/8 节点 url-test 失败 | `url: https://www.gstatic.com/generate_204` 被某些 CF 边缘节点屏蔽 | 改为 `http://www.google.com`，8/8 全部通过 |
| 3 | fast-open=true 导致回退 | V2Ray 服务端默认 fastOpen=false，客户端提前发数据导致连接断开 | 设为 `false` |
| 4 | v2fly v2ray 5.53.0 不支持 httpupgrade | v2fly 移除了 httpupgrade 传输层（v2rayN 使用的是 v2fly v4） | 放弃用 v2ray-core 做 E2E 测试，直接用 clashmi 验证 |
| 5 | sing-box 下载失败 | GitHub Releases 被阻断、NAS wget 卡 0 字节、sftp 上传 QNAP 有兼容问题 | 放弃二进制下载，按用户指示改为对照已有配置 diff |
| 6 | rule-provider clashmi 不加载 | clashmi 不支持 `rule-provider` 外部下载 | 改为服务端硬编码内联规则 |
| 7 | 全量规则 334K 行太大 | Loyalsoldier 全套规则集过大 | 精选 330+ 条日常规则 |
| 8 | QNAP sftp put 失败 | paramiko `sftp.put` 报 OSError "Failure"，QNAP sftp 实现不标准 | 改用 `put /tmp` → cp 到目标路径 |
| 9 | `domain:*.douyin.com` 写法错误 | V2Ray 路由 `domain` 本身包含子域名匹配，`*` 被当作字面量 | 改为 `domain:douyin.com` |
| 10 | `.pyc` 缓存不更新 | systemd ExecStart 指向 `.py`，但之前误操作编译了 `.pyc` 覆盖 | 直接 cp `.py` 到目标路径，不依赖 `.pyc` |

---

## 12. 文件清单

| 文件 | 说明 |
|------|------|
| `local/sub_proxy.py` | 核心：订阅拉取 → 解密 → 格式转换 → HTTP 服务（977 行） |
| `local/sub-proxy.service` | systemd 服务定义 |
| `local/ssh_exec.py` | NAS SSH 部署脚本（paramiko） |
| `local/mihomo_transport.md` | Mihomo 传输层配置官方文档（基准参考） |
| `local/last_good.txt` | 上次刷新成功的 CN 节点列表（磁盘持久化） |
| `local/our_clash.yaml` | 生成的 Clash YAML 样本（330+ 规则） |
| `local/our_clash_live.yaml` | 从 NAS 实时拉取的 YAML（验证用） |
| `local/other_vendor_clash.yaml` | 第三方可用 Mihomo 配置（对照参考） |
| `local/clash_screenshot.jpg` | clashmi 节点测试截图（3/8 正常时的状态） |
| `local/dump_nodes.py` | vmess 链接解码/打印工具 |
| `local/dns_check8.py` | 8 节点域名 DNS 存活检查 |
| `local/probe_origins.py` | 节点 HTTP 连通性探测 |
| `local/verify_deploy.py` | 部署后校验脚本 |
| `local/verify_clash2.py` | Clash YAML 生成校验脚本 |
| `local/check_failed.py` | 失败节点特征分析脚本 |

---

> 本文档记录了从 APK 逆向到 Clash 可用配置的完整过程，核心发现包括：
> 1. AES-256-CBC 解密密钥和 IV 从 APK 反编译提取
> 2. Mihomo 不直接支持 httpupgrade，需映射为 `ws + v2ray-http-upgrade: true`
> 3. url-test 应使用 `http://www.google.com` 而非 `gstatic.com`
> 4. clashmi 不支持外部 rule-provider 下载，规则需内联硬编码
> 5. V2Ray 路由 domain 匹配天然包含所有子域名