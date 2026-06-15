# SecureChat 信令安全

本文档记录阶段 2 的信令安全改动。它单独放在 README 之外，便于在报告中引用安全模型和实现说明。

## 信令承载的内容

信令通道是 Host/Client 和不可信 Server 之间的 WebSocket 连接。它承载：

- 创建房间和加入房间请求；
- opaque room token、username 和房间访问 token；
- 必填 PKI `identity` 对象；
- 成员加入/离开状态；
- Host 拒绝身份验证失败成员的 `reject_client`；
- Host 发起的 `silence_client` / `unsilence_client` 当前房间禁言控制；
- Host 发起的 `gka_request`、Client 发给 Host 的 `gka_contribution` envelope；
- Host 发给 Client 的 `group_key`/group-state envelope；
- opaque `encrypted_relay` envelope。

创建/加入房间和成员状态不是聊天消息，但仍然敏感。Host/Client 会先把 roomId 和房间密码派生为 opaque room token，Server 用该 token 注册和路由房间；加密中继 envelope 的连接 id、大小和时序仍可能暴露通信模式。`encrypted_relay` envelope 是应用层密文，Server 只负责转发。

## WS 模式

`ws://` 是基于 TCP 的明文 WebSocket。HTTP upgrade 握手以及之后的 WebSocket frame 都不会经过 TLS 加密。

风险：

- 能观察网络路径的人可以读取房间密码；
- room token、username、成员状态和中继 metadata 可见；
- 路径上的主动攻击者可以篡改信令流量；
- 抓包可以直接看到 `type`、opaque `roomId` token、`username`、`password` token、`senderId`、`ciphertext` 等 JSON 字段。

SecureChat 保留 WS 作为明确标注的 insecure mode。它运行更简单，不需要证书或域名，但信令流量是明文。真实公网部署如果要求信令保密，不应使用该模式。

## WSS 模式

`wss://` 是运行在 TLS 之上的 WebSocket。TLS 会保护 HTTP upgrade 以及之后所有 WebSocket frame。在 SecureChat 中，WSS 通过 libdatachannel 原生的 `rtc::WebSocketServer::Configuration` 实现：

- `enableTls = true`；
- `certificatePemFile = SECURECHAT_TLS_CERT_FILE`；
- `keyPemFile = SECURECHAT_TLS_KEY_FILE`；
- 可选 `keyPemPass = SECURECHAT_TLS_KEY_PASS`。

优点：

- 房间密码跨网络传输时受到保护；
- room token、username、成员状态和中继 metadata 不会被被动网络观察者直接读取；
- 使用受信任证书和匹配域名时，客户端可以进行基于证书的服务器身份校验；
- 对信令流量的主动篡改会被 TLS 检测到。

限制：

- WSS 不能替代端到端加密；它只保护信令 WebSocket 在网络传输中的机密性和完整性；
- 文本和附件 metadata/chunk 使用应用层加密中继，Server 不持有 room group key，不能解密群聊内容；私发还有 pairwise 内层密钥，Server/Host/其他成员不能解开目标成员的私发正文或附件；
- 当前 GKA v3 已实现成员 public key、签名 contribution、Host 发起 epoch 和成员变化后的 key rotation；PKI 成员身份签名证书强制绑定 `join_room` public key、GKA contribution 和 `group_key`/group-state envelope；
- 服务器 IP、连接时间、流量大小等元数据仍可能被观察；
- 自签名证书适合测试，但除非客户端显式信任，否则不能提供正常公网身份校验。

## Nginx TLS 反向代理

```text
Host/Client -- WSS --> Nginx -- local WS --> SecureChat Server
```

Nginx 可以监听公网 `25566`，完成 TLS 终止和 WebSocket upgrade，再把流量转发到本机 `ws://127.0.0.1:25567`。Server 仍只负责房间注册、成员状态和不透明加密中继。反向代理只改变传输入口，不改变应用层 PKI、GKA 和加密中继的安全边界。

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

GKA v3 不再要求成员手工配置共享 E2EE 口令。Client 加入时提交临时 X25519 public key；Host 在成员变化时发起 GKA epoch；当前成员提交签名随机 contribution；Host 汇总贡献集合后通过 `group_key`/group-state envelope 分别封装给当前成员。Client 解封装 group state、验证贡献签名后本地导出 room group key。Server 负责转发这些 envelope，群密钥生成和密钥协商状态由 Host/Client 本地维护。Host 维护 GKA watchdog；如果某个 Client 在 10 秒内没有提交当前 epoch 的有效 contribution，Host 会驱逐该成员、封当前房间内的证书指纹，并用剩余成员重新发起 epoch。

Client 会在 `join_room` 中附带成员证书链和签名，Host 验证证书链、有效期、Key Usage 和签名后才信任该临时 X25519 public key。成员 GKA contribution 也带签名，Host 和 Client 都会验证。Host 发送 `group_key` envelope 时附带 Host 身份签名，Client 验证通过后才解封装 group state。Server 只要求相关 identity 字段结构和大小合法；证书链验证发生在 Host/Client 本地，Server 不参与身份语义。

Server 的 `room_members.memberInfos` 会转发 Client 入房时提交的 `publicKey` 和 signed `identity`，让其他 Client 自行验证成员公钥。Host 的加密 `member_identity` 控制消息也会携带同样材料；接收端会拒绝同一个 member id 上的公钥或证书指纹冲突。私发只有在目标成员 public key 已验证时才会发送，否则失败关闭。

这里的“Server 不验证证书”指 Server 不验证应用层成员身份证书链，即 `identity.certChainPem`。Server 不检查 CA、有效期、Key Usage 或 identity 签名；这些都由 Host/Client 完成。TLS 服务器证书属于传输层入口身份，不属于 SecureChat Server 的应用层成员身份验证。

## 房间治理信令

Host 可以通过普通输入框发送以下本地管理命令：

```text
/silence <member>
/unsilence <member>
/evict <member>
/ban <member>
```

`/silence` 和 `/unsilence` 会转换为 Host 到 Server 的 `silence_client` / `unsilence_client` 信令。Server 验证发送方确实是当前 room 的 Host 后，只在当前房间内记录目标 clientId 的发送限制。被禁言 Client 保持连接，可以继续参与后续 GKA epoch，但它发送 `encrypted_relay` 时 Server 返回 `member is silenced`，不会转发文本或附件。

`/evict` 和 `/ban` 使用现有 `reject_client` 关闭目标 Client WebSocket。Host 同时把该成员已经通过 PKI 验证的证书 SHA-256 指纹记录到当前房间内存封禁集中。相同证书再次加入时，Host 会在验证 identity 后拒绝该成员，不记录 public key，也不允许其参与 GKA epoch。该封禁不写入磁盘，Host 进程或房间结束后失效。

## 恶意 Server 行为边界

Server 可以断开连接、丢弃消息或伪造成员离线，这属于可用性和房间状态层风险。当前实现做了以下收敛：

- Server 不能在不破坏 PKI 签名的情况下静默替换 `join_room.publicKey`、GKA contribution 或 `group_key`/group-state envelope；
- Host 收到未知或过期 `client_left` 时不会移除成员，也不会触发 group key rotation；
- Host/Client 解密私发中继消息后检查 `relayTargetId`，目标不是自己时丢弃，不展示 UI；
- 私发中继消息的内层 `pairwise_private` 不从 room group key 派生，没有目标成员私钥的端点无法解密；
- Host/Client 维护最近中继 nonce/tag cache，重复 envelope 会被丢弃；
- Client 检查递增 `group_key.epoch`，拒绝旧 group state 回滚；
- Client 只把入房失败和 `host disconnected` 等明确终止事件作为 shutdown；非终止类中继错误只提示，不主动离开房间；
- Server 仍能对已知成员伪造断线通知或直接断开连接，这会导致 Host 移除该成员并轮换 group key；这是可用性攻击，不能由应用层密码学完全阻止。
