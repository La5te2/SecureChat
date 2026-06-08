# SecureChat 信令安全

本文档记录阶段 2 的信令安全改动。它单独放在 README 之外，便于在报告中引用安全模型和实现说明。

## 信令承载的内容

信令通道是在 WebRTC DataChannel 建立之前使用的 WebSocket 连接。它承载：

- 创建房间和加入房间请求；
- room id、username 和房间密码；
- SDP offer 和 answer；
- ICE candidate。

这些内容不是聊天消息，但仍然敏感。房间密码属于凭据；SDP/ICE 可能暴露端点和网络元数据。

## WS 模式

`ws://` 是基于 TCP 的明文 WebSocket。HTTP upgrade 握手以及之后的 WebSocket frame 都不会经过 TLS 加密。

风险：

- 能观察网络路径的人可以读取房间密码；
- SDP 和 ICE 元数据可见；
- 路径上的主动攻击者可以篡改信令流量；
- 抓包可以直接看到 `type`、`roomId`、`username`、`password`、`sdp`、`candidate` 等 JSON 字段。

SecureChat 保留 WS 作为明确标注的 insecure mode。它运行更简单，不需要证书或域名，但信令流量是明文。真实公网部署如果要求信令保密，不应使用该模式。

## WSS 模式

`wss://` 是运行在 TLS 之上的 WebSocket。TLS 会保护 HTTP upgrade 以及之后所有 WebSocket frame。在 SecureChat 中，WSS 通过 libdatachannel 原生的 `rtc::WebSocketServer::Configuration` 实现：

- `enableTls = true`；
- `certificatePemFile = SECURECHAT_TLS_CERT_FILE`；
- `keyPemFile = SECURECHAT_TLS_KEY_FILE`；
- 可选 `keyPemPass = SECURECHAT_TLS_KEY_PASS`。

优点：

- 房间密码跨网络传输时受到保护；
- SDP 和 ICE 元数据不会被被动网络观察者直接读取；
- 使用受信任证书和匹配域名时，客户端可以进行基于证书的服务器身份校验；
- 对信令流量的主动篡改会被 TLS 检测到。

限制：

- WSS 不能让云端 Host 无法读取应用层消息；
- WSS 不能替代端到端加密；
- 服务器 IP、连接时间、流量大小等元数据仍可能被观察；
- 自签名证书适合测试，但除非客户端显式信任，否则不能提供正常公网身份校验。

## 为什么 WS 和 WSS 不在同一个端口

明文 WS 和 WSS 使用不同握手。当前 C++ server 的单个监听端口只能是明文 WebSocket 或 TLS WebSocket。要同时保留两种模式，可以：

- 在一个端口运行 WS insecure mode，例如 `25566`；
- 在另一个端口运行 WSS secure mode，例如 `25567`；
- 或停止当前模式后切换配置并重启 Host。

## 部署变量

WS mode 是默认值，便于保留本地和无证书环境的简单用法，但它已经明确标注为 insecure mode。

启用 WSS mode：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=/path/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/path/privkey.pem
./start.sh
```

客户端随后使用：

```text
wss://your-domain.example:25566
```

应使用与证书匹配的域名。像 `124.70.71.65` 这样的公网 IP 通常无法通过正常证书校验，除非证书明确覆盖该 IP。

## 密码处理

`start.sh` 优先使用终端隐藏输入，并通过短生命周期本地管道把房间密码传给 Host。这避免密码暴露在 argv 中，也避免 Host 进程环境变量长期保留 `SECURECHAT_ROOM_PASSWORD`。`SECURECHAT_ROOM_PASSWORD` 仍可用于非交互自动化兼容，但不是首选交互路径。
