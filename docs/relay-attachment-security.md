# SecureChat Relay 数据通路与附件安全

本文档对应 `todolist.md` 的阶段 3 和阶段 4，用于说明当前真实拓扑、GKA v2 数据通路，以及附件安全边界。

## 阶段 3：角色模型

当前采用三个明确角色：

```text
Server：只提供监听、房间注册、成员连接状态、密文 relay；不创建群密钥，不参与密钥协商语义，不是群成员
Host：创建 roomId，是第一个群成员/群管理者；发起并协调 Group Key Agreement；使用协商出的对称 group key 加解密消息和附件
Client：加入 room，提交成员 public key，接收 Host 封装的 group key；使用同一个 group key 加解密消息和附件
```

`Server` 的职责是公网可达、房间注册、成员状态维护，以及 opaque encrypted relay 转发。`Host` 和 `Client` 才是可见聊天成员。这样论文中的安全边界更清楚：攻破或托管 `Server` 不应得到应用层文本、附件明文或 room group key。

同一个 Server 实例可以承载多个不同 `roomId`，但同一个 Server 实例内 `roomId` 不能重复；不同 Server 或不同端口上的房间名可以重复。一台主机可以开多个 Server，只要监听端口不同。

## 当前数据拓扑

文本和附件的数据路径是：

```text
Host member  <->  Server opaque encrypted_relay  <->  Client member(s)
```

Server 会校验 WebSocket 会话所属 room 和 sender identity，然后转发 envelope；Server 不解密 ciphertext。Host/Client 使用当前 room group key 解密应用消息。

已完成的数据通路分离：

- 文本消息通过 `encrypted_relay` 转发。
- `/image`、`/file`、`/voice` 的 metadata 通过 `image_meta`、`file_meta`、`voice_meta` 加密后转发。
- `/image`、`/file`、`/voice` 的 binary chunk 通过 `image_binary`、`file_binary`、`voice_binary` 加密后转发。
- Host/Client 不再建立 WebRTC PeerConnection/DataChannel。
- Server 不再接受或转发 `offer`、`answer`、`ice`。

## GKA v2

当前 GKA v2 是 Host 协调的 group key 分发模型：

1. Client 本地生成临时 X25519 key pair。
2. Client 在 `join_room` 中提交 public key；启用 PKI 时同时提交成员身份签名。
3. Server 校验房间密码和成员状态，只把 public key 作为成员元数据转交给 Host。
4. Host 生成 32-byte room group key。
5. Host 为每个 Client public key 生成临时 X25519 key pair，通过 X25519 + HKDF-SHA256 派生 wrapping key。
6. Host 用 AES-256-GCM 把 room group key 封装成 `group_key` envelope；启用 PKI 时同时附加 Host 身份签名，经 Server 转发给目标 Client。
7. Client 启用 PKI 时先验证 Host 身份签名，再用自己的 X25519 private key 解开 `group_key` envelope，得到当前 room group key。
8. 文本和附件都用 room group key 做 AES-256-GCM。

成员变化时：

- 新成员加入：Host 记录该成员 public key，轮换新的 room group key，并发给当前所有 Client。
- 成员离开：Host 删除该成员 public key，轮换新的 room group key，并发给剩余 Client。
- 历史消息对曾持有旧 key 的成员无法撤回；轮换只保护后续消息。

## Envelope

应用层消息先在 Host/Client 本地序列化为 JSON，再加密封装为：

```json
{
  "type": "encrypted_relay",
  "version": 2,
  "roomId": "secure-room",
  "senderId": "client-id-or-host",
  "senderName": "display-name",
  "senderKind": "host-or-client",
  "targetId": "",
  "alg": "AES-256-GCM",
  "kdf": "GKA-X25519-HKDF-SHA256",
  "nonce": "base64",
  "ciphertext": "base64",
  "tag": "base64"
}
```

`targetId` 为空表示群发；填写 `host` 或某个 clientId 时，Server 会校验目标成员是否仍在房间内，并只转发给该目标。`targetId` 被绑定进 AES-GCM AAD，Server 不能在不破坏认证标签的情况下静默把一条密文改投给另一个目标。

当前私发是 group key 下的定向投递，不是独立点对点私聊密钥。也就是说，普通 Server 仍看不到明文；但如果恶意 Server 把私发密文复制给其他仍持有当前 room group key 的成员，该成员理论上可以解密。要达到更强的私聊隔离，需要后续引入 pairwise key、sender key 或独立会话密钥。

Host 发给单个 Client 的 group key envelope：

```json
{
  "type": "group_key",
  "version": 2,
  "roomId": "secure-room",
  "targetId": "client-id",
  "senderId": "host",
  "alg": "AES-256-GCM",
  "kdf": "X25519-HKDF-SHA256",
  "ephemeralPublicKey": "base64",
  "nonce": "base64",
  "ciphertext": "base64",
  "tag": "base64",
  "identity": {
    "version": 1,
    "certChainPem": "pem",
    "nonce": "base64",
    "signatureAlg": "Ed25519",
    "signature": "base64"
  }
}
```

`identity` 只在启用 PKI 身份认证时出现。Server 转发 `group_key` 前会用 WebSocket 会话状态覆盖 `roomId`、`senderId` 和 `targetId`，避免发送方伪造这些明文 metadata。转发 `encrypted_relay` 时，Server 会覆盖 `senderId`、`senderName` 和 `senderKind`。私发时 Server 使用 `targetId` 做成员存在性校验和定向转发。AAD 不作为 JSON 字段传输，而是在 Host/Client 本地按固定格式重新构造。

Client 加入时的 `join_room` 也可以携带同形状的 `identity` 对象。Server 只校验字段结构和大小；Host/Client 本地完成证书链、吊销列表、签名算法和签名内容验证。

## Server 可见与不可见内容

Server 可见：

- room id；
- sender id、sender name、sender kind；
- 私发 relay envelope 的目标 member id；
- group key envelope 的目标 client id；
- envelope 算法名、KDF 名、nonce、tag；
- ciphertext 长度、消息数量和转发时序；
- WebSocket 连接来源和在线状态。

Server 不应可见：

- room group key；
- 聊天文本；
- 原始附件文件名；
- 附件 mime；
- 附件二进制内容；
- 附件 metadata 明文。

## 阶段 4：附件安全现状

当前附件实现位于 `src/attachment_transfer.cpp`。

已实现：

- 单个发送附件默认大小限制：100 MB，可用 `SECURECHAT_ATTACHMENT_MAX_BYTES` 覆盖。
- 发送端和接收端都会检查扩展名白名单。
- 图片文件头校验：PNG、JPEG、BMP。
- 语音文件头校验：WAV。
- 文本类文件按文本附件处理，不执行、不自动打开。
- 接收文件只写入项目运行目录下的 `logs/images`、`logs/voice`、`logs/files`。
- 接收文件名会去除路径分隔符和 Windows 不允许的字符，限制长度，并处理 Windows 保留文件名，降低路径穿越和特殊文件名风险。
- `logs/` 和子目录会尽量设置为 owner-only 权限。
- 新附件接收前会检查 `logs/` 缓存总量，超限时只在 `logs/images`、`logs/voice`、`logs/files` 中删除最旧缓存文件。

默认缓存总量上限：

```text
512 MB
```

可以通过环境变量覆盖：

```bash
export SECURECHAT_LOGS_MAX_BYTES=1073741824
```

## 限制

文件头校验不是杀毒。它只能降低明显伪装文件进入图片/语音渲染路径的风险，不能保证文件内容安全。接收者仍不应信任陌生文件，也不应把收到的文件交给高权限程序自动打开。

附件进入 `logs/` 也意味着成员本机会留下解密后的内容缓存。E2EE 保护的是网络路径和不可信 Server 不读明文；它不能保护已经收到并解密的成员设备。

当前仍需诚实说明的限制：

- 未启用 PKI 身份认证时，X25519 member key 是会话临时 key，尚未绑定长期身份、证书或可人工核验的指纹。
- 未启用 PKI 且不使用可信 `wss://` 时，路径上的主动攻击者或恶意 Server 可能替换 Client public key，诱导 Host 给攻击者封装 group key。
- 启用 PKI 后，成员身份证书链和签名可以绑定 `join_room` public key 与 `group_key` envelope；Server 仍不参与证书验证。
- Server 仍可观察 room、sender、连接时间、ciphertext 大小和消息时序等元数据。
