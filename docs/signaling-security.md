# SecureChat 信令安全

本文档记录阶段 2 的信令安全改动。它单独放在 README 之外，便于在报告中引用安全模型和实现说明。

## 信令承载的内容

信令通道是 Host/Client 和不可信 Server 之间的 WebSocket 连接。它承载：

- 创建房间和加入房间请求；
- room id、username 和房间密码；
- 成员加入/离开状态；
- opaque `encrypted_relay` envelope。

创建/加入房间和成员状态不是聊天消息，但仍然敏感。房间密码属于凭据；relay envelope 的 room/sender metadata、大小和时序也可能暴露通信模式。`encrypted_relay` envelope 是应用层密文，Server 只负责转发。

## WS 模式

`ws://` 是基于 TCP 的明文 WebSocket。HTTP upgrade 握手以及之后的 WebSocket frame 都不会经过 TLS 加密。

风险：

- 能观察网络路径的人可以读取房间密码；
- room、username、成员状态和 relay metadata 可见；
- 路径上的主动攻击者可以篡改信令流量；
- 抓包可以直接看到 `type`、`roomId`、`username`、`password`、`senderId`、`ciphertext` 等 JSON 字段。

SecureChat 保留 WS 作为明确标注的 insecure mode。它运行更简单，不需要证书或域名，但信令流量是明文。真实公网部署如果要求信令保密，不应使用该模式。

## WSS 模式

`wss://` 是运行在 TLS 之上的 WebSocket。TLS 会保护 HTTP upgrade 以及之后所有 WebSocket frame。在 SecureChat 中，WSS 通过 libdatachannel 原生的 `rtc::WebSocketServer::Configuration` 实现：

- `enableTls = true`；
- `certificatePemFile = SECURECHAT_TLS_CERT_FILE`；
- `keyPemFile = SECURECHAT_TLS_KEY_FILE`；
- 可选 `keyPemPass = SECURECHAT_TLS_KEY_PASS`。

优点：

- 房间密码跨网络传输时受到保护；
- room、username、成员状态和 relay metadata 不会被被动网络观察者直接读取；
- 使用受信任证书和匹配域名时，客户端可以进行基于证书的服务器身份校验；
- 对信令流量的主动篡改会被 TLS 检测到。

限制：

- WSS 不能替代端到端加密；它只保护信令 WebSocket 在网络传输中的机密性和完整性；
- 文本和附件 metadata/chunk 现在已有应用层 encrypted relay，Server 不持有 room group key，不能解密应用内容；
- 当前 GKA v2 已实现成员 public key、Host 分发 group key 和成员变化后的 key rotation；尚未实现长期身份密钥、指纹校验或证书绑定；
- 服务器 IP、连接时间、流量大小等元数据仍可能被观察；
- 自签名证书适合测试，但除非客户端显式信任，否则不能提供正常公网身份校验。

## 为什么 WS 和 WSS 不在同一个端口

明文 WS 和 WSS 使用不同握手。当前 C++ server 的单个监听端口只能是明文 WebSocket 或 TLS WebSocket。要同时保留两种模式，可以：

- 在一个端口运行 WS insecure mode，例如 `25566`；
- 在另一个端口运行 WSS secure mode，例如 `25567`；
- 或停止当前模式后切换配置并重启 Server。

## 部署变量

WS mode 是默认值，便于保留本地和无证书环境的简单用法，但它已经明确标注为 insecure mode。

启用 WSS mode：

```bash
export SECURECHAT_SIGNALING_TLS=1
export SECURECHAT_TLS_CERT_FILE=certs/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=certs/privkey.pem
./start_server.sh --mode wss
```

客户端随后使用：

```text
wss://chat.la5te2.online:25566
```

应使用与证书匹配的域名。像 `124.70.71.65` 这样的公网 IP 通常无法通过正常证书校验，除非证书明确覆盖该 IP。

## 密码处理

`start_server.sh` 不需要房间密码，默认把不可信 Server 作为 daemon 常驻。`start_host.sh` 和 `start_client.sh` 默认前台运行，由底层 CLI 隐藏提示房间密码；只有显式 `--daemon` 时，脚本才通过短生命周期本地管道传递房间密码，避免密码暴露在 argv 中，也避免子进程环境变量长期保留 `SECURECHAT_ROOM_PASSWORD`。`SECURECHAT_ROOM_PASSWORD` 仍可用于非交互自动化，但不是首选交互路径。

GKA v2 不再要求成员手工配置共享 E2EE 口令。Client 加入时提交临时 X25519 public key，Host 生成并轮换 room group key，再通过 `group_key` envelope 分别封装给当前成员。Server 只转发这些 envelope，不创建群密钥，也不参与密钥协商语义。

注意：当前成员 public key 仍是会话临时 key，尚未绑定长期身份。公网部署应使用可信 `wss://`，否则路径上的主动攻击者或恶意 Server 可能替换 public key，诱导 Host 给攻击者封装 group key。
