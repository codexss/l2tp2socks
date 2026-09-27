# l2tp2socks

把一个**不使用 IPsec 的 L2TPv2 VPN**转换为本地 SOCKS5 代理。程序在进程内完成
L2TP、PPP 和 TCP/IP 处理，不创建设备、不修改系统路由，也不需要 root、
`CAP_NET_ADMIN` 或 `/dev/net/tun`。

项目架构参考了 [ExpTechTW/proxygate](https://github.com/ExpTechTW/proxygate)：
VPN 会话向 SOCKS5 层提供标准的 `DialContext`/`ListenPacket` 接口。与参考项目不同，
这里的客户端直接使用 UDP/1701 上的 L2TPv2，不进行 IKE、ESP 或 IPsec 封装。

> [!WARNING]
> 纯 L2TP **不加密，也不验证服务器身份**。VPN 用户名、认证交换和业务流量均可能被
> 旁路观察或篡改。只应在受信任的隔离网络中使用，或在 WireGuard、TLS、SSH 等加密
> 外层隧道中承载。不要直接穿越不可信互联网。

## 功能

- 纯用户态 L2TPv2 LAC，默认连接 UDP/1701
- PPP LCP、MS-CHAPv2 和 IPCP
- gVisor 用户态 TCP/IP 栈，无需管理员权限
- SOCKS5 `CONNECT` 和 `UDP ASSOCIATE`
- 可选 SOCKS5 用户名/密码认证
- 支持 DNS-over-HTTPS；DoH TLS 连接也经 VPN 发送，并使用固定 bootstrap IP
- 可退回 VPN 内普通 UDP DNS，均不会调用主机 DNS
- macOS、Linux 和 Windows 可编译运行

当前限制：仅支持 IPv4；PPP 认证目前要求服务端支持 MS-CHAPv2；不支持 SOCKS5
UDP 分片；每次运行维护一个 L2TP 会话。

## 构建

需要 Go 1.26.6 或更高版本：

```sh
make test
make build
```

生成的程序位于 `build/l2tp2socks`。仓库包含经过修改的 govpn 依赖，确保纯 L2TP
数据通道可复现构建。

## 配置与运行

```sh
cp config.example.json config.json
# 编辑 config.json，填写 L2TP 地址和账号
./build/l2tp2socks -config ./config.json
```

验证 TCP 代理：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

配置字段：

- `l2tp.server`：L2TP 服务器 IPv4 地址或域名
- `l2tp.port`：L2TP UDP 端口，通常为 `1701`
- `l2tp.username` / `l2tp.password`：PPP 凭据
- `l2tp.mtu`：用户态接口 MTU，范围 `576..1400`
- `l2tp.connectTimeout`：协商超时，例如 `30s`
- `l2tp.dnsServer`：通过 VPN 访问的 DNS UDP 地址
- `l2tp.dohUrl`：RFC 8484 DoH 地址；非空时优先使用 DoH
- `l2tp.dohBootstrapIp`：DoH 服务的固定 IPv4 地址，防止解析 DoH 域名时先发生 DNS 泄漏或污染
- `socks5.listen`：代理监听地址，默认仅本机 `127.0.0.1:1080`
- `socks5.username` / `socks5.password`：可选代理认证；监听非回环地址时强制要求

默认使用 Cloudflare DoH：

```json
"dohUrl": "https://cloudflare-dns.com/dns-query",
"dohBootstrapIp": "1.1.1.1"
```

如需改用普通 UDP DNS，把 `dohUrl` 和 `dohBootstrapIp` 都设为空字符串；
`dnsServer` 仍经 L2TP VPN 访问，不会走主机默认 DNS。

## Docker

容器同样不需要特权模式或额外 capabilities：

```sh
docker build -t l2tp2socks .
docker run --rm \
  -v "$PWD/config.json:/config/config.json:ro" \
  -p 127.0.0.1:1080:1080 \
  l2tp2socks
```

容器内监听需要把 `socks5.listen` 改成 `0.0.0.0:1080` 并设置 SOCKS5 用户名和密码。

## 实现说明

数据路径为：

```text
SOCKS5 客户端 → gVisor TCP/UDP → IPv4 → PPP → L2TPv2 → UDP/1701 → L2TP 服务器
```

L2TP 控制消息使用 `Ns/Nr`、确认和重传；PPP 完成 LCP、MS-CHAPv2 与 IPCP 后，
分配到的 IPv4 地址被安装到进程内 gVisor 网络栈。整个过程不会触碰主机路由表。

## 许可证

本项目使用 AGPL-3.0。第三方来源及许可证见 [NOTICE](NOTICE) 和
`third_party/govpn/LICENSE`。
