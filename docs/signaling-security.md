# SecureChat 信令安全

本文档说明 SecureChat 的信令通道、WSS 入口和不可信 Server 边界。

## 信令承载的内容

信令通道是 Host/Client 和不可信 Server 之间的 WebSocket 连接。它承载：

- 创建房间和加入房间请求；
- opaque room instance token、username 和房间访问状态；
- 必填 PKI `identity` 对象；
- 成员加入/离开状态；
- Host 拒绝身份验证失败成员的 `reject_client`；
- Host 发起的 `silence_client` / `unsilence_client` 当前房间禁言控制；
- Host 显式关闭房间的 `close_room` 控制消息；
- Server 发给成员的 `host_disconnected` 和 `room_closed` 状态；
- Host 发起的 `gka_request`、Client 发给 Host 的 `gka_contribution` envelope；
- Host 发给 Client 的 `group_key`/group-state envelope；
- opaque `encrypted_relay` envelope。

创建/加入房间和成员状态不是聊天消息，但仍然敏感。CLI 的 room-dir 路径和 WinUI 的自动 entrance 导入流程都会读取 opaque room instance token，Server 用该 token 注册和路由房间；加密中继 envelope 的连接 id、大小和时序仍可能暴露通信模式。`encrypted_relay` envelope 是应用层密文，Server 只负责转发。

## WSS 信令模式

当前正式对外信令入口使用 `wss://`。Host/Client/WinUI 只校验 URL 语法，接受 `ws://` 和 `wss://`；明文入口由 Server 启动配置决定。Server 默认启用 TLS；`SECURECHAT_SIGNALING_TLS=0` 要求 loopback 绑定，并提供本机回环 WS backend。

原因：

- 暴露在公网或跨主机网络上的明文 WebSocket 会暴露 HTTP upgrade、信令 JSON、room token、连接状态和中继 metadata；
- 路径上的主动攻击者可以篡改未受 TLS 保护的信令；
- 当前房间准入和成员身份已经依赖 PKI/GKA，继续保留明文信令只会增加误用入口。

`wss://` 是运行在 TLS 之上的 WebSocket。TLS 会保护 HTTP upgrade 以及之后所有 WebSocket frame。在 SecureChat 中，WSS 通过 libdatachannel 原生的 `rtc::WebSocketServer::Configuration` 实现：

- `enableTls = true`；
- `certificatePemFile = SECURECHAT_TLS_CERT_FILE`；
- `keyPemFile = SECURECHAT_TLS_KEY_FILE`；
- 可选 `keyPemPass = SECURECHAT_TLS_KEY_PASS`。

优点：

- room instance token 和入房控制信令在网络传输中受到保护；
- room token、username、成员状态和中继 metadata 不会被被动网络观察者直接读取；
- 使用受信任证书和匹配域名时，客户端可以进行基于证书的服务器身份校验；
- 对信令流量的主动篡改会被 TLS 检测到。

限制：

- WSS 不能替代端到端加密；它只保护信令 WebSocket 在网络传输中的机密性和完整性；
- 文本和附件 metadata/chunk 使用应用层加密中继，Server 不持有 room group key，不能解密群聊内容；私发还有 pairwise 内层密钥，Server/Host/其他成员不能解开目标成员的私发正文或附件；
- 当前 GKA v3 已实现成员 public key、签名 contribution、Host 发起 epoch 和成员变化后的 key rotation；PKI 成员身份签名证书强制绑定 `join_room` public key、GKA contribution 和 `group_key`/group-state envelope；
- 服务器 IP、连接时间、流量大小等元数据仍可能被观察；
- 本地自签名证书适合本机或局域网运行；公网入口应使用系统信任 CA 签发的证书。

## Nginx TLS 反向代理边界

```text
Host/Client -- WSS/protected tunnel --> fronting component -- local WS --> SecureChat Server
```

Nginx/Caddy 可以监听公网入口，完成外部 TLS 和 WebSocket upgrade，再把流量转发到本机 SecureChat Server。frp、SSH tunnel 等受保护隧道也可以作为外层接入组件。此时 SecureChat Server 可用 `SECURECHAT_SIGNALING_TLS=0` 监听 `127.0.0.1` WS backend。Server 仍只负责房间注册、成员状态和不透明加密中继。外层组件只改变传输入口，应用层 PKI、GKA 和加密中继安全边界保持一致。具体部署命令见 `docs/startup-guide.md`，证书获取和文件边界见 `docs/certificate-methods.md`。

## 密码处理

`start_server.sh` 不需要房间密码，默认把不可信 Server 作为 daemon 常驻。Host/Client CLI 使用 `--room-dir` 读取房间级 PKI 和 room instance token，不再从环境变量或 stdin 读取房间密码。

GKA 由当前成员的签名随机贡献共同生成 room group key。Client 加入时提交临时 X25519 public key；Host 在成员变化时发起 GKA epoch；当前成员提交签名随机 contribution；Host 汇总贡献集合后通过 `group_key`/group-state envelope 分别封装给当前成员。Client 解封装 group state、验证贡献签名后本地导出 room group key。Server 负责转发这些 envelope，群密钥生成和密钥协商状态由 Host/Client 本地维护。Host 维护 GKA watchdog；如果某个 Client 在 10 秒内没有提交当前 epoch 的有效 contribution，Host 会驱逐该成员、封当前房间内的证书指纹，并用剩余成员重新发起 epoch。

Client 会在 `join_room` 中附带成员证书链和签名，Host 验证证书链、有效期、Key Usage 和签名后才信任该临时 X25519 public key。成员 GKA contribution 也带签名，Host 和 Client 都会验证。Host 发送 `group_key` envelope 时附带 Host 身份签名，Client 验证通过后才解封装 group state。Server 只要求相关 identity 字段结构和大小合法；证书链验证发生在 Host/Client 本地，Server 不参与身份语义。

Server 的 `room_members.memberInfos` 会转发 Client 入房时提交的 `publicKey` 和 signed `identity`，让其他 Client 自行验证成员公钥。Host 的加密 `member_identity` 控制消息也会携带同样材料；接收端会拒绝同一个 member id 上的公钥或证书指纹冲突。私发只有在目标成员 public key 已验证时才会发送，否则失败关闭。

这里的“Server 不验证证书”指 Server 不验证应用层成员身份证书链，即 `identity.certChainPem`。Server 不检查 CA、有效期、Key Usage 或 identity 签名；这些都由 Host/Client 完成。TLS 服务器证书属于传输层入口身份，不属于 SecureChat Server 的应用层成员身份验证。

## 房间治理信令

Host 可以通过普通输入框发送以下本地管理命令：

```text
/silence <fingerprint-prefix>
/unsilence <fingerprint-prefix>
/evict <fingerprint-prefix>
/ban <fingerprint-prefix>
/list
/approve <request-id>
/reject <request-id> [reason]
/stop_session
/close_room
```

`/silence` 和 `/unsilence` 会转换为 Host 到 Server 的 `silence_client` / `unsilence_client` 信令。Host 本地先用至少 8 位证书指纹前缀解析目标成员。Server 验证发送方确实是当前 room 的 Host 后，只在当前房间内记录目标 clientId 的发送限制。被禁言 Client 保持连接，可以继续参与后续 GKA epoch，但它发送 `encrypted_relay` 时 Server 返回 `member is silenced`，不会转发文本或附件。

`/evict` 和 `/ban` 使用现有 `reject_client` 关闭目标 Client WebSocket。Host 同时把该成员已经通过 PKI 验证的证书 SHA-256 指纹记录到当前房间内存封禁集中。相同证书再次加入时，Host 会在验证 identity 后拒绝该成员，不记录 public key，也不允许其参与 GKA epoch。该封禁不写入磁盘，Host 进程或房间结束后失效。

新成员发送 `join_room` 后先进入 `pending_join`。Server 为该次入房申请生成 `requestId`，它只是 pending join 的内部审批 id，不是成员身份、密钥或聊天内容。Server 只保存和转发该 opaque 请求，不给 pending 成员下发 group key。首次导入 `entrance.scp` 的 Client 会把 CSR bundle、设备声明和 join proof 放入 admission-encrypted payload；该 payload 使用 admission secret 经 HKDF-SHA256 派生 AES-256-GCM key 加密。Host 解密后验证 CSR、成员声明、room instance 绑定和 pending join proof，可以用 `/list` 查看 pending requestId，再用 `/approve <request-id>` 在线签发成员证书响应，并发送带 Host 签名的 `approve_join`；WinUI Host 左键 pending 成员卡片时会在内部使用对应 requestId。签发响应同样放入 admission-encrypted payload。验证失败或 Host 主动拒绝时使用 `/reject <request-id>` 发送带签名的拒绝响应。Client 收到 `joined` 后会解密并安装签发响应，再验证 Host 的 approval 签名，验证通过才进入 active 成员状态。

私发消息和私发附件的目标使用证书指纹前缀，前缀至少 8 位十六进制字符，大小写不敏感。nickname、displayName、base username 和 system username 都不作为私发路由目标。WinUI 左键成员卡片复制证书指纹前 8 位，完整指纹保留在程序内部；Host 可以通过 `/list` 显式查看完整指纹。

`/stop_session` 和 `/close_room` 会转换为 Host 到 Server 的 `close_room` 信令。该控制消息包含 Host 房间级证书签名，签名内容绑定 room instance token、动作类型、epoch 和 payload digest。Server 验证发送连接是当前 room 的 Host 后，广播 `room_closed` 并移除该房间；Client 本地验证 Host 签名后才接受房间关闭事件。Host 关闭 WinUI、Ctrl+C、进程退出或网络瞬断不会发送 `close_room`，Server 只广播 `host_disconnected` 并保留房间状态。Host 用同一 room token 重新连接时可以重新接管房间；Host 会从 `room_members` 重新验证已有 Client identity，再发起后续 GKA。

## 恶意 Server 行为边界

Server 可以断开连接、丢弃消息或伪造成员离线，这属于可用性和房间状态层风险。当前实现做了以下收敛：

- Server 不能在不破坏 PKI 签名的情况下静默替换 `join_room.publicKey`、GKA contribution 或 `group_key`/group-state envelope；
- Host 收到未知或过期 `client_left` 时不会移除成员，也不会触发 group key rotation；
- Host/Client 解密私发中继消息后检查 `relayTargetId`，目标不是自己时丢弃，不展示 UI；
- 私发中继消息的内层 `pairwise_private` 不从 room group key 派生，没有目标成员私钥的端点无法解密；
- Host/Client 维护最近中继 nonce/tag cache，重复 envelope 会被丢弃；
- Client 检查递增 `group_key.epoch`，拒绝旧 group state 回滚；
- Client 只把入房失败、`room_closed` 和 Host 拒绝等明确终止事件作为 shutdown；`host_disconnected` 只显示状态，不主动离开房间；
- Server 仍能对已知成员伪造断线通知或直接断开连接，但 Host 只把它视为 connection disconnected，不自动吊销成员资格或封禁证书；这仍然是可用性攻击，不能由应用层密码学完全阻止。

