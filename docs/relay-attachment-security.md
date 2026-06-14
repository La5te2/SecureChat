# SecureChat Relay 数据通路与附件安全

本文档对应 `todolist.md` 的阶段 3、阶段 4 和阶段 12，用于说明当前真实拓扑、GKA v3 数据通路，以及附件安全边界。

## 阶段 3：角色模型

当前采用三个明确角色：

```text
Server：只提供监听、房间注册、成员连接状态、密文 relay；不创建群密钥，不参与密钥协商语义，不是群成员
Host：创建 roomId，是第一个群成员和房间生命周期管理者；发起 GKA epoch，汇总签名贡献集合；使用协商出的对称 group key 加解密群聊消息和附件，私发时使用 pairwise 内层密钥
Client：加入 room，提交成员 public key，参与 GKA epoch；使用 group key 加解密群聊消息和附件，私发时用目标成员已验证 public key 派生 pairwise key
```

`Server` 的职责是公网可达、房间注册、成员状态维护，以及 opaque encrypted relay 转发。`Host` 和 `Client` 才是可见聊天成员。这样论文中的安全边界更清楚：攻破或托管 `Server` 不应得到应用层文本、附件明文或 room group key。

同一个 Server 实例可以承载多个不同 room token，但同一个 Server 实例内 token 不能重复；不同 Server 或不同端口上的房间名可以重复。一台主机可以开多个 Server，只要监听端口不同。Host/Client 本地保留真实 roomId，Server 注册和路由只看到由 roomId 和房间密码派生出的 opaque room token。

## 当前数据拓扑

文本和附件的数据路径是：

```text
Host member  <->  Server opaque encrypted_relay  <->  Client member(s)
```

Server 会校验 WebSocket 会话所属 room token 和 sender connection id，然后转发 envelope；Server 不解密 ciphertext。Host/Client 使用当前 room group key 解密群聊应用消息；私发在外层 group key relay 内还需要目标成员 pairwise private key。

已完成的数据通路分离：

- 文本消息通过 `encrypted_relay` 转发。
- `/image`、`/file`、`/voice` 的 metadata 通过 `image_meta`、`file_meta`、`voice_meta` 加密后转发。
- `/image`、`/file`、`/voice` 的 binary chunk 通过 `image_binary`、`file_binary`、`voice_binary` 加密后转发。
- Host/Client 不再建立 WebRTC PeerConnection/DataChannel。
- Server 不再接受或转发 `offer`、`answer`、`ice`。

## GKA v3

当前 GKA v3 是 Host 发起的贡献式 group key 协商模型：

1. Client 本地生成临时 X25519 key pair。
2. Client 在 `join_room` 中提交 public key 和成员身份签名。
3. Server 校验 room token 和成员状态，只把 public key 作为成员元数据转交给 Host。
4. Host 发起新的 `gka_request` epoch。
5. 每个当前成员生成 32-byte contribution secret，并用成员身份私钥签名。
6. Client 把签名 contribution 用 Host 的 X25519 public key 加密成 `gka_contribution`，经 Server 转发给 Host。
7. Host 汇总完整 contribution set，派生当前 `K_G`，并把完整 group state 用每个 Client public key 单独封装成 `group_key` envelope。
8. Client 先验证 Host 身份签名，再用自己的 X25519 private key 解开 group state，逐个验证成员 contribution 签名，然后本地派生当前 room group key。
9. 群聊文本和附件都用 room group key 做 AES-256-GCM；私发再叠加 pairwise 内层 AES-256-GCM。

成员变化时：

- 新成员加入：Host 记录该成员 public key，发起新的 GKA epoch，并把新 group state 发给当前所有 Client。
- 成员离开：Host 删除该成员 public key，发起新的 GKA epoch，并只发给剩余 Client。
- 成员被 Host `/evict` 或 `/ban`：Host 删除该成员 public key，发起新的 GKA epoch，并把该成员证书指纹加入当前房间内存封禁集。
- 成员被 Host `/silence`：只禁止其发送文本和附件，不改变成员资格，因此不轮换 room group key。
- 历史消息对曾持有旧 key 的成员无法撤回；轮换只保护后续消息。
- 恶意成员如果拒绝提交 GKA contribution，会造成可用性问题；当前 Host 在 10 秒 GKA 超时后自动驱逐未贡献成员，并用剩余成员重新发起 epoch。

## Envelope

应用层消息先在 Host/Client 本地序列化为 JSON，再加密封装为：

```json
{
  "type": "encrypted_relay",
  "version": 3,
  "roomId": "opaque-room-token",
  "senderId": "client-id-or-host",
  "alg": "AES-256-GCM",
  "kdf": "GKA-Contrib-v3-HKDF-SHA256",
  "nonce": "base64",
  "ciphertext": "base64",
  "tag": "base64"
}
```

应用层 senderName、senderKind 和 targetId 都在解密后的 Message payload 内。群发 payload 中 targetId 为空；私发 payload 中 targetId 为 `host` 或某个 clientId。Server 不读取 targetId，也不按私发目标定向转发 `encrypted_relay`。

私发使用双层保护。外层仍是 room group key 的 `encrypted_relay`，用于统一走 Server broadcast relay；内层是 `pairwise_private`，由发送者临时 X25519 private key 和目标成员已验证 public key 派生 pairwise key 后加密原始文本或附件消息。Host/Client 先检查解密 payload 中的 `relayTargetId`，目标不是自己时丢弃；即使恶意 Server 把外层 envelope 复制给其他成员，其他成员也缺少内层 pairwise 私钥材料，不能解开私发正文或附件 chunk。

Server 仍可见 room token、sender connection id、ciphertext 长度和转发时序。这些元数据不会暴露消息内容，但会暴露活跃时间和大致附件大小。

Host 发给单个 Client 的 group-state envelope：

```json
{
  "type": "group_key",
  "version": 3,
  "epoch": 1,
  "roomId": "opaque-room-token",
  "targetId": "client-id",
  "senderId": "host",
  "alg": "AES-256-GCM",
  "kdf": "X25519-HKDF-SHA256+GKA-Contrib-v3",
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

`identity` 是 `join_room`、GKA contribution 和 `group_key` 的必需字段。Server 转发 `group_key` 前会用 WebSocket 会话状态覆盖 `roomId`、`senderId` 和 `targetId`，避免发送方伪造这些明文 metadata。转发 `encrypted_relay` 时，Server 只覆盖 `roomId` 和 `senderId`；senderName、senderKind、targetId 都留在加密 payload 内。如果发送方是被 Host 禁言的 Client，Server 在 relay 前拒绝该 envelope。AAD 不作为 JSON 字段传输，而是在 Host/Client 本地按固定格式重新构造。

`room_members.memberInfos` 会携带 Host/Client 入房时提交的 `publicKey` 和 signed `identity`。接收端不信任 Server 对成员公钥的陈述，而是重新验证 identity 签名后才把 member id/name 映射到 pairwise public key。GKA group state 中的 contribution identity 也会被复验。Host 的加密 `member_identity` 控制消息同样不能静默覆盖已有的已验证公钥或证书指纹。

Client 加入时的 `join_room` 也可以携带同形状的 `identity` 对象。Server 只校验字段结构和大小；Host/Client 本地完成证书链、有效期、Key Usage、签名算法和签名内容验证。

## Server 可见与不可见内容

Server 可见：

- opaque room token；
- sender connection id；
- group key envelope 的目标 client id；
- envelope 算法名、KDF 名、nonce、tag；
- ciphertext 长度、消息数量和转发时序；
- WebSocket 连接来源和在线状态。

Server 不应可见：

- room group key；
- GKA contribution secret；
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
- WinUI 成员默认 Allowed，成员卡片为绿色；右键成员卡片可切换为 Blocked 红色状态，禁止该成员附件自动预览。
- WinUI 提供自动预览图片、自动加载音频两个开关。
- WinUI 预览前会再次检查图片尺寸、总像素数、文件大小，以及 WAV 采样率、声道数、时长和 chunk 结构。

默认缓存总量上限：

```text
512 MB
```

可以通过环境变量覆盖：

```bash
export SECURECHAT_LOGS_MAX_BYTES=1073741824
```

## WinUI 成员附件预览状态

WinUI 的附件预览策略是本机 UI 状态，不参与 PKI 验证或密钥协商：

- Allowed：默认状态，成员卡片为绿色；图片/音频按设置面板的自动预览开关处理。
- Blocked：本机用户右键成员卡片后进入该状态，成员卡片为红色；图片/音频只显示附件卡片，不自动进入本地解码器。再次右键恢复 Allowed。
- 自己本地选择并发送的附件按“本地文件”处理，不证明该成员可信。

默认配置为：图片自动预览开、音频自动加载关。因此默认情况下，Allowed 成员发来的图片可在结构校验通过后自动预览，音频仍显示附件卡片；Blocked 成员始终不自动预览。

WinUI 中的 `MaxPreviewImageBytes` 和 `MaxPreviewAudioBytes` 只限制本地预览，不限制协议传输。协议传输统一由 `SECURECHAT_ATTACHMENT_MAX_BYTES` 控制。一个附件可能被允许接收，但因为尺寸、像素数、WAV 结构或预览大小上限而不被 WinUI 自动预览。

## 限制

文件头校验不是杀毒。它只能降低明显伪装文件进入图片/语音渲染路径的风险，不能保证文件内容安全。接收者仍不应信任陌生文件，也不应把收到的文件交给高权限程序自动打开。

附件进入 `logs/` 也意味着成员本机会留下解密后的内容缓存。E2EE 保护的是网络路径和不可信 Server 不读明文；它不能保护已经收到并解密的成员设备。

当前仍需诚实说明的限制：

- 成员身份证书链和签名绑定 `join_room` public key 与 `group_key` envelope；Server 仍不参与证书验证。
- Server 仍可观察 room、sender、连接时间、ciphertext 大小和消息时序等元数据。
