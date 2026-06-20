# SecureChat 安全待办清单中文版

本文档用于跟踪“设计安全的双向通信软件”这一项目主题下的安全风险、解决方案和推进步骤。

## 开发目标

近期工程目标是做出一个可以在局域网和公网使用的安全双向通信系统。客户端在发送前对文本、图片、语音和文件进行应用层端到端加密；Server 只承担连接协调、房间状态维护和密文中继职责；房间成员在本地完成身份验证、密钥协商、消息解密和附件安全处理。

长期目标是把 SecureChat 推进为 trust-minimized autonomous secure communication system。系统最终希望让用户只需要信任自己的本地客户端、本机私钥、本地策略和公开协议规则；Server、网络、Host、其他房间成员和附件来源都通过密码学证明、协议状态、transcript、capability、阈值确认和本地安全策略来约束。

目标设计包括：

- 文本、图片、语音和文件在离开本机前完成应用层加密。
- 不可信 Server 和信令/中继服务只处理 opaque room token、连接状态、密文长度和转发时序等必要元数据。
- 成员身份、房间准入、密钥协商、成员变更和控制消息都绑定房间实例状态，防止跨房间替换、重放和降级。
- Host 负责创建房间和显式关闭房间；长期方向中，Host 的权力逐步被 capability、多签、阈值确认和成员本地验证约束。
- 附件在本地按来源证书标识来源，所有 file 附件默认按有风险文件隔离落地，后续通过平台权限标记、隔离目录和受控打开策略支持敏感内容和危险性附件的传递。
- 系统设计保持可解释、可复现和可测试，避免把安全性建立在无法审计的隐藏假设上。

这意味着云服务器最终是可替换的不可信协调者和密文中继，而不是聊天信任根；Host 是某个房间实例的创建者和治理角色，而不是所有成员必须永久信任的中心。

## 学习方向

目标：后续协议演进应追求“用清晰的协议结构获得更高通信安全强度”。重点是理解现代安全协议如何用成熟密码原语、状态绑定、多方确认和可验证状态转移减少信任假设，而不是堆砌彼此割裂的安全组件。

- 密码学基础。
  - 数论基础：模运算、群、有限域。
  - 概率基础：随机变量、信息熵、生日攻击。
  - 对称加密：AES-GCM、nonce、AEAD、认证加密。
  - 哈希函数：SHA-256、碰撞、预像、HMAC。
  - 密钥派生：HKDF、salt、info、domain separation。
  - 公钥密码：DH、ECDH、椭圆曲线、X25519。
  - 数字签名：Ed25519、ECDSA、签名不可伪造性。
  - PKI：证书链、CA、CSR、吊销、pinning。

- 安全协议设计。
  - 威胁模型、身份认证、密钥确认、前向安全、后向安全。
  - 重放攻击、降级攻击、中间人攻击、Unknown Key-Share 攻击、Key Compromise Impersonation。
  - Transcript binding、channel binding、domain separation、state machine security。
  - 重点学习 TLS 1.3、Signal Double Ratchet、Messaging Layer Security、Noise Protocol Framework、SSH host key pinning、Certificate Transparency 的设计思想。

- 群组通信协议。
  - Group Key Agreement、TreeKEM、MLS epoch、member add/remove/update。
  - Forward secrecy、post-compromise security、group transcript、commit/proposal 模型。
  - 重点吸收 MLS 的 epoch、group context、confirmed transcript hash、member set hash、commit signature 等概念。

- 多签名、阈值签名和秘密共享。
  - Shamir Secret Sharing。
  - Schnorr signature。
  - MuSig2。
  - FROST threshold signature。
  - BLS signature aggregation。
  - Threshold CA。
  - Distributed Key Generation。
  - 项目应用方向包括多人共同签发成员证书、多人确认 Host 重入、Root/Intermediate 私钥分片备份、房间管理动作多签确认。

- 形式化验证和协议分析。
  - 学习 Verifpal、Tamarin Prover、ProVerif、CryptoVerif。
  - 优先用 Verifpal 建模简单握手、Host 重入、GKA epoch、控制消息签名和重放攻击。
  - BAN logic 只作为历史背景了解。

- 实现安全。
  - 常量时间比较。
  - 安全随机数 CSPRNG。
  - nonce 管理。
  - 密钥擦除。
  - 内存安全。
  - canonical encoding。
  - 错误处理和日志脱敏。
  - 版本协商和降级保护。
  - 项目重点关注 nonce 不重复、HKDF context 绑定、签名内容 canonical、证书指纹和 member id 映射不可替换、错误消息不泄露私发行为。

- 推荐学习材料。
  - Serious Cryptography。
  - Cryptography Engineering。
  - RFC 8446 TLS 1.3 的 handshake 和 key schedule。
  - Noise Protocol Framework。
  - Signal Double Ratchet 说明和论文。
  - RFC 9420 Messaging Layer Security 的 group context、epoch 和 TreeKEM。
  - Shamir Secret Sharing、Schnorr、MuSig2、FROST。
  - Verifpal 或 Tamarin 的入门示例。

- 研究定位。
  - 底层密码算法采用成熟实现，避免把安全性建立在未充分验证的自制密码原语上。
  - 项目创新重点放在协议组合、成员准入、密钥更新、身份绑定、群状态一致性验证、低交互多签治理和嵌入式附件隔离上。
  - 长期探索方向包括自治房间治理、可验证房间状态、room-local capability、资源预算、阈值签发、Host 权力约束和恶意 Server 环境下的状态一致性。

## 设计原则

- 使用成熟密码库，不手写密码算法。
- 在应用层使用 AEAD 加密消息和附件。
- 明确区分信令、密钥协商、加密数据传输。
- 诚实说明限制：IP 地址、时间、消息大小、在线状态等元数据仍可能可见。
- 当前以贡献式 GKA v3 作为可展示的 E2EE 主线：成员签名随机贡献、Host 发起 epoch 并转发贡献集合、成员本地导出 room group key；私发在 room relay 外层内再使用 pairwise key。

## 当前基线

- 文本消息已通过 Server opaque encrypted relay 双向可用，不再存在 Host/Client DataChannel 数据通路。
- 图片、语音、文件附件 metadata 和 binary chunk 已通过 Server opaque encrypted relay 双向可用，不再存在 Host/Client DataChannel 附件通路。
- 局域网内，只要 TCP 信令/relay 端口可达，通信可用。
- 公网使用不可信 Server 时，需要：
  - TCP `25566` 可达，用于信令、成员状态和 encrypted relay。
  - 不需要 STUN、UDP ICE 候选端口或 WebRTC/DataChannel 建连。
- 当前 Server/Host 进程职责已拆开；文本和附件数据通路已进入 Server 密文 relay 形态。
- 当前文本消息和附件已走 Server opaque encrypted relay，Server 不能解密应用层内容。
- GKA v3 已实现成员 public key、签名贡献、Host 发起 epoch、成员加入/离开后的 group key rotation。
- PKI 身份认证已作为 Host/Client 必需配置，实现成员证书签名、`join_room` public key 绑定、`group_key` Host 签名和当前房间内证书指纹封禁。

## 安全模型

### 保护资产

- 聊天文本。
- 图片、语音、文件附件。
- 房间密码。
- 用户身份/用户名。
- 服务器上的 `logs/` 文件。
- Host 进程可用性。

### 信任边界

- 本地客户端。
- 局域网。
- 公网。
- 不可信 Server。
- 信令通道。
- WebSocket 信令和 encrypted relay。
- 本地文件系统和日志。

### 当前可以声明的安全属性

- 文本和附件 metadata/chunk 已使用应用层 AES-256-GCM AEAD 加密。
- 房间密码限制普通用户加入房间。
- 附件有类型、大小和基础文件头校验。
- 云安全组和 Linux 防火墙能缩小网络暴露面。

### 当前不能安全声明的内容

- Host/Client 缺少完整 PKI 身份配置时启动失败，不能退回无成员身份绑定模式。
- 使用 `ws://` 时不能声称信令保密。
- 文件类型校验不等于恶意文件检测。
- 不能声称仓库本身已经替部署者完成云安全组来源 IP 收敛或生产级运维体系。

### 目标 E2EE 声明

实现 E2EE 后，希望能声明：

- 网络监听者、中继服务器、云信令服务器不能读取消息和附件内容。
- 它们仍可能看到 IP、连接时间、消息大小和在线状态等元数据。
- 拥有群组密钥的成员可以读取当前群消息。
- 如果成员设备被攻破，E2EE 无法保护该设备上可见的明文。

## 阶段 1：凭据处理

目标：避免房间密码通过命令行历史、进程列表或日志泄漏。

- [x] 不再推荐直接把密码放在命令行。
  - 风险：
    ```bash
    ./host --server ws://127.0.0.1:25566 secure-room host 123456
    ```
    会把 `123456` 暴露在 shell history 或 `ps`。
  - 状态：Host/Client CLI 已移除 `[password]` 参数；多传命令行密码会打印 usage 并退出。

- [x] 支持隐藏输入、stdin 密码管道和 `SECURECHAT_ROOM_PASSWORD` 非交互路径。
  - 首选用法：直接运行 `./start_host.sh` 或 `./start_client.sh`，由 CLI 隐藏读取密码。
  - 非交互首选用法：
    ```bash
    printf '%s\n' 'strong-password' | ./start_host.sh --server ws://127.0.0.1:25566 --daemon
    ```
  - 注意：环境变量适合少量自动化场景，但不是首选交互方式；读取后 CLI 会尽快从当前进程环境中清掉该变量。

- [x] 增加隐藏密码输入。
  - Host 和 Client CLI 在交互式终端中会提示 `Room password:`，输入时不会回显。
  - Host 和 Client CLI 支持从 stdin 读取非交互密码，`start_host.sh` 和 `start_client.sh` 的 `--daemon` 模式已使用该路径，避免子进程继承密码环境变量。
  - 不再保留默认房间密码 fallback。

- [x] 检查当前 Host/Client 路径，避免记录密码。
  - 当前错误信息只显示密码错误，不打印用户输入的房间密码。
  - Host/Client 发出 `create_room`/`join_room` 后会清空会话对象里的密码字符串。
  - SignalingServer 的房间注册表只保存 room id 加盐后的 SHA-256 密码摘要，不保存房间密码明文。
  - 剩余风险：`ws://` 信令在升级为 `wss://` 前仍是明文。

- [x] 默认不保存 daemon 日志。
  - 风险：`server.log`、`host.log`、`client.log` 会记录 room id、用户名、成员变化和连接状态等房间运行信息。
  - 方案：`start_server.sh`、`start_host.sh --daemon`、`start_client.sh --daemon` 默认把输出写入 `/dev/null`；只有显式设置对应日志环境变量时才保存诊断日志。
  - 日志只用于临时排障，排障后应删除，不能当作长期审计日志。

- [x] 真实部署密码设计方案。
  - 使用高强度随机密码。
  - 不写入 README、`.bashrc`、命令行参数或长期日志。
  - 交互启动时由 Host/Client CLI 隐藏读取。
  - 非交互启动优先用一次性 stdin 管道；环境变量只作为自动化路径，避免写入 shell 启动文件。
  - SignalingServer 内部只保存房间密码摘要，不保存明文。
  - 剩余风险：输入端设备、root 用户、core dump、WSS 关闭时的网络明文。

## 阶段 2：信令安全

目标：保护创建/加入房间、成员状态和 encrypted relay 过程，降低监听和篡改风险。

- [x] 支持 `wss://` secure mode，同时保留 `ws://` insecure mode。
  - `ws://` 优点：配置简单，不需要证书或域名，适合本地、内网和明文传输观察。
  - `ws://` 风险：房间密码、成员状态和 relay envelope metadata 都在明文 WebSocket 中传输。
  - `wss://` 优点：用 TLS 保护信令传输，降低监听和篡改风险。
  - `wss://` 限制：需要证书和匹配域名；不能替代应用层 E2EE。
  - 状态：`SignalingServer` 已支持 libdatachannel 原生 TLS，详见 `docs/signaling-security.md`。

- [x] 严格校验信令消息。
  - 当前已有 JSON 大小和结构预算校验。
  - 当前已增加按消息类型的字段白名单、必填字段和字符串长度限制。
  - 当前已具备基础字段校验和坏消息限制；更细的用户名策略和来源 IP 级别限速未纳入当前阶段范围。

- [x] 增加信令限速。
  - 风险：公网端口会被扫描或垃圾请求占用。
  - 方案：限制连接数、失败次数、无效 JSON 次数。

- [x] 增加信令角色约束。
  - Host-only：只有 Host WebSocket 可以创建对应 roomId，并作为该房间第一个成员。
  - Client-only：Client 只能加入已存在的 roomId，并以 Server 分配的 clientId 发送 relay。
  - Server 会用 WebSocket 会话状态覆盖 encrypted relay 的 sender metadata，避免伪造 `from`、跨房间或跨角色注入。

- [x] 保持异常连接清理。
  - 当前已有 `connectionTimeout = 15s`，避免半开或废弃 WebSocket 握手长期占用信令入口。
  - `SignalingServer` 已在 `onClosed` 和 `onError` 回调中调用 `cleanup()`，移除 `mClients`、房间成员、离线状态，并在 Host 断开时关闭房间。
  - 重复无效信令达到阈值后会主动关闭 WebSocket；状态清理依赖随后触发的关闭回调。
  - 已增加维护线程：每 15 秒扫描已关闭 WebSocket 并兜底调用 `cleanup()`；每分钟输出低频健康日志，包含连接数、房间数、房间成员数和本轮清扫数量。

## 阶段 3：Server/Host/Client 边界与拓扑安全

目标：明确真实拓扑，并逐步实现严格 E2EE。

### 已完成

- [x] 引入 Server/Host/Client 三角色模型。
  - `Server`：只提供监听、房间注册、成员连接状态、密文 relay；不创建群密钥，不参与密钥协商语义，不是群成员。
  - `Host`：创建 roomId，是第一个群成员/群管理者；发起并协调 Group Key Agreement；使用协商出的对称 group key 加解密消息。
  - `Client`：加入 room，参与 Group Key Agreement；使用同一个 group key 加解密消息和附件。
  - 状态：已写入 `docs/relay-attachment-security.md`。

- [x] 完成 Server/Host 进程职责拆分。
  - `server <port>` 只运行信令/协调服务，不从 stdin 发送聊天内容，不作为 room member 注册。
  - `host --server <ws-url> <room> [username]` 可作为群主成员连接外部 Server。
  - 启动层只保留 Server、Host、Client 三组明确角色脚本和对应 CLI 路径。
  - 同一 Server 实例支持多个不同 `roomId`；同一实例内 `roomId` 不可重复，不同 Server/端口上的 roomId 可重复。

- [x] 实现文本消息 encrypted relay。
  - 文本消息通过 `encrypted_relay` envelope 由 Server 转发。
  - Host/Client 使用 GKA v3 得到的 room group key 执行 AES-256-GCM。
  - Server 绑定 sender metadata 到 WebSocket 会话状态，但不解密 ciphertext。
  - 文本目标拓扑已经落地：
    ```text
    Host member  <->  Server opaque encrypted_relay  <->  Client member(s)
    ```

- [x] 完成附件数据通路分离：让 Server 转发附件密文 chunk。
  - `/image`、`/file` 和 WinUI 按住录音产生的 voice metadata/binary chunk 已封装进 `encrypted_relay`。
  - Host/Client DataChannel 建连逻辑已从主流程移除。
  - Server 只看到 room/sender metadata、ciphertext 大小和转发时序，不能解密原始文件名、mime、文本内容或二进制内容。

- [x] 附件也要加密。
  - 图片、语音、文件的 metadata 和 binary chunks 已使用与文本相同的应用层 relay AEAD。
  - 接收端解密后仍会把附件写入本地 `logs/` 缓存，因此本地设备和群成员仍是信任边界。

- [x] 写入 E2EE 目标架构和 envelope 草案。
  - 目标文档已明确：`wss://` 不能替代应用层 E2EE。
  - 目标文档已明确：Server 未来可以协调/转发，但不能解密消息和附件。
  - envelope 草案已写入 `docs/relay-attachment-security.md`，文本消息已按该方向实现。

- [x] 清理 WebRTC/DataChannel 旧连接层。
  - Host/Client 不再创建 PeerConnection/DataChannel。
  - Server 不再接受或转发 `offer`、`answer`、`ice`。
  - STUN、ICE candidate 和 UDP 端口不再属于当前运行模型。

### 已完成的 E2EE v3 / GKA 细节

- [x] 实现贡献式 GKA v3：成员临时 X25519 public key + 签名随机贡献 + Host 发起 epoch。
  - `room password` 只用于房间访问控制；Host/Client 本地把 roomId 和 password 派生为 opaque room token 后交给 Server。
  - Client 加入时生成临时 X25519 key pair，并在 `join_room` 中提交 public key 和成员身份签名。
  - Server 只校验房间和成员状态，并把 Client public key 转交给 Host。
  - Host 发起 `gka_request`，当前成员生成 32-byte contribution secret 并用成员身份私钥签名。
  - Client 的 `gka_contribution` 用 Host 的 X25519 public key 加密，Server 只转发密文。
  - Host 汇总完整签名贡献集合后，通过 `group_key` envelope 单独封装 group state 给每个 Client。
  - Client 用本地 private key 解开 group state，逐个验证贡献签名，再本地导出 room group key。
  - 文本和附件均使用 room group key 做 AES-256-GCM。

- [x] 成员变化后密钥轮换。
  - 新成员加入：Host 记录 public key，发起新的 GKA epoch，并把新 group state 发给当前所有 Client。
  - 成员离开：Host 删除该成员 public key，发起新的 GKA epoch，并只发给剩余 Client。
  - 历史消息对曾持有旧 key 的成员无法撤回；轮换只保护后续消息。

- [x] 实现应用层加密消息 envelope。
  - 当前 encrypted relay envelope 字段：
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
  - Server 会用 WebSocket 会话状态覆盖 `roomId` 和 `senderId`；应用层 senderName、senderKind 和 targetId 都在密文 payload 内，AAD 由 Host/Client 本地隐式构造。
- [x] 实现私发消息和附件。
  - `/to <member> <message>` 支持 Host/Client 私发文本。
  - `/to <member> /image <path>`、`/to <member> /file <path>` 支持 CLI 私发附件；WinUI Voice 可通过私信目标框发送按住录音。
  - WinUI 发送栏支持 `To: member` 目标输入；留空群发，填写成员名私发。
  - Server 广播外层密文；`targetId` 在加密 payload 内，接收端解密后检查目标，不属于自己的私发直接丢弃。
  - 私发正文和附件 chunk 额外使用发送者临时 X25519 key 与目标成员已验证 public key 派生 pairwise key，不降级为仅 room group key 私发。

### 阶段 3 安全边界

PKI 身份认证现在强制绑定成员证书、临时 public key、GKA contribution 和 Host `group_key`/group-state envelope。私发已有 pairwise 内层密钥隔离；Server/Host/其他成员即使拿到外层 room relay，也不能解开目标成员的私发内容。仍需明确的边界包括：Server 可见 room token、连接 id、ciphertext 大小和时序等元数据；Server 可以断连、丢弃或重放旧 envelope；Host 仍是房间生命周期管理者和 GKA epoch 发起者，但不再单方生成 room group key。

## 阶段 4：附件安全

目标：在保留图片、语音、文件功能的同时降低恶意文件风险。

- [x] 保留附件语义校验。
  - 图片：扩展名限制为 PNG/JPG/JPEG/BMP，并要求文件头与扩展名一致。
  - 语音：只由 WinUI 按住录音生成 WAV，并校验 RIFF/WAVE 文件头；CLI 不提供 `/voice <path>`。
  - 文件：作为通用任意文件附件通道，不限制扩展名或格式，后续由隔离目录、权限标记和打开策略处理风险。
  - 发送端和接收端都会执行校验，native 校验是最终防线。
- [x] 统一附件发送大小限制。
  - 图片、语音、文件附件共用 `SECURECHAT_ATTACHMENT_MAX_BYTES`。
  - 默认单个附件上限为 100 MB。
- [x] 确认文件名安全，避免路径穿越。
  - 接收端只取文件名，不信任发送方路径。
  - 路径分隔符、控制字符和 Windows 不允许的字符会替换为 `_`。
  - Windows 保留名会回退到默认文件名。
  - 接收文件名会限制长度，并在本地缓存名前加入时间和唯一序号，避免同名覆盖。
- [x] 附件进入 `logs/`，不自动执行、不自动打开。
  - 接收目录按 room instance 分层：`logs/images/<room>_<roomInstanceTokenDigest前8位>`、`logs/voice/<room>_<roomInstanceTokenDigest前8位>`、`logs/files/<room>_<roomInstanceTokenDigest前8位>`。
  - UI 不执行附件；普通文件只显示附件提示。
  - 图片和语音先按附件卡片展示，预览动作只触发本地图片/音频解码器，不启动外部程序。
- [x] 增加 WinUI 附件预览安全策略。
  - 成员默认 Allowed，成员卡片为绿色；右键成员卡片切换 Blocked 红色状态，再次右键恢复 Allowed。
  - 成员列表只显示 name；点击成员卡片复制完整证书指纹，不直接显示长 id 或长指纹。
  - Blocked 只保存在当前会话内存中，退出、断开或切换房间后清空。
  - 设置面板提供“自动预览图片”“自动加载音频”两个开关。
  - WinUI 预览前额外检查图片宽高、总像素数、预览文件大小，以及 WAV 采样率、声道数、时长和 chunk 结构。
  - `MaxPreviewImageBytes`、`MaxPreviewAudioBytes` 只限制本地预览，不改变 `SECURECHAT_ATTACHMENT_MAX_BYTES` 的统一传输限制。
- [x] 增加 `logs/` 总大小限制或清理策略。
  - 默认缓存上限为 512 MB。
  - 可通过 `SECURECHAT_LOGS_MAX_BYTES` 覆盖。
  - 新附件接收前会在受管理的附件缓存目录中删除最旧文件，无法释放空间时拒绝接收。
- [x] 明确说明文件校验不是杀毒。
  - 状态：已写入 `docs/relay-attachment-security.md`。

## 阶段 5：本地运行痕迹与秘密输入

目标：减少密码、日志、附件缓存和进程运行环境在本机或云服务器上留下的可恢复痕迹。

- [x] 避免密码进入命令行参数。
  
  - Host/Client CLI 已移除 `[password]` 参数。
- [x] 优先使用隐藏输入和 stdin 管道传递 Host/Client 密码。
  - Host/Client 交互模式默认隐藏读取密码。
  - Host/Client daemon 模式通过 stdin 接收密码，不继承 `SECURECHAT_ROOM_PASSWORD`。
- [x] 收束 daemon stdout/stderr 日志。
  
  - Server daemon 默认写入 `server/logs/server.log`，可通过 `SECURECHAT_SERVER_LOG_ENABLED=0` 关闭输出。
  - Host/Client daemon 日志仍只用于临时排障。
- [x] 不用 root 长期运行。
  - `start_server.sh` 默认拒绝 root 运行；确需临时诊断时才设置 `SECURECHAT_ALLOW_ROOT=1`。
  - `docs/deployment-hardening.md` 已给出 `securechat` 专用用户部署步骤。
- [x] 设置 `logs/` 权限，例如：
  ```bash
  chmod 700 /SecureChat/logs
  ```
  - 状态：附件接收目录创建时会尽量设置为 owner-only 权限；Windows 上标准权限调用可能是 no-op，仍依赖系统账户权限。
- [x] 降低 shell history 和复制粘贴泄漏风险。
  - 不使用 `export SECURECHAT_ROOM_PASSWORD=...` 作为交互首选方式。
  - 需要自动化时，优先使用 stdin 管道；`docs/deployment-hardening.md` 已写入历史清理建议。
- [x] 提供可选 systemd 服务模板。
  - `deploy/securechat-server.service` 已给出非 root 用户、失败重启和基础权限收敛配置。
  - systemd 是 Linux 服务管理器，只改善进程监督和权限边界；它不会提供通信内容保密，不能替代 WSS 或应用层 E2EE。
- [x] 排障后按需删除日志；长期日志轮转不是当前默认路径。
  
  - `docs/deployment-hardening.md` 已给出 `server.log`、`host.log`、`client.log` 清理命令。

## 阶段 6：UI 安全和隐私

目标：让 GUI 行为符合安全预期。

- [x] WinUI 默认不显示低层 log。
  - 状态：WinUI 聊天区已过滤 native `log`。
- [x] WinUI 不显示 endpoint 噪声。
  - 状态：WinUI 聊天区过滤 `client ws://...` 和 endpoint 信息；房间面板只保留模式、房间和参与者。
- [x] 消息、图片、语音、文件气泡显示发送者。
  - 状态：WinUI 从 decrypted message payload 的 `displayName` 或 attachment sender 队列显示发送者。
- [x] 清晰区分：
  - signaling connected。
  - room joined。
  - encrypted relay ready。
- [x] 文件选择器和 native 校验语义一致。
  - 状态：WinUI 图片选择器限制为图片格式；普通文件选择器允许任意文件；语音由 WinUI 按住录音生成，不再打开音频文件选择器。native 校验仍是最终防线。
- [x] Host/Join 输入框不预填敏感或环境相关信息。
  - Host 和 Join 的 Room、Server URL、User 默认均为空。
  - Join 面板顺序已调整为 Room、Server URL、User、Password，与 Host 面板一致。

## 阶段 7：可用性和稳定性

目标：让公网 Server 和成员连接不容易因为异常连接卡住。

- [x] 保持 WebSocket send 不在 `mMutex` 内执行。
  
  - 状态：Server 先在锁内复制目标 WebSocket 和消息快照，释放锁后调用 `safeSend()`。
- [x] Server 增加低频健康日志。
  
  - 状态：维护线程每分钟输出连接数、房间数、房间成员数和清扫数量；日志默认不落盘，只在显式启用日志时用于诊断。
- [x] 如果启用 systemd，服务模板包含失败重启：
  ```ini
  Restart=on-failure
  RestartSec=3
  ```
- [x] 提供 SIGTERM 优雅关闭验证路径。
  - Server/Host/Client CLI 都注册 SIGTERM/SIGINT 处理；stop 脚本先发 SIGTERM，超时后才 SIGKILL。
  - `docs/deployment-hardening.md` 已给出 `stop_server.sh` 和 `systemctl stop` 后检查 `25566` 释放的命令。
- [x] 删除 DataChannel 连接层。
  
  - 应用层数据已经迁移到 encrypted relay；Host/Client 不再建立 DataChannel。

## 阶段 8：部署卫生

目标：在不深改协议的情况下，让当前 Server 更适合作为实验公网服务运行。

当前仓库已提供手动 daemon、非 root guard、可选 systemd 模板和部署加固文档。云安全组来源 IP 收敛需要在云控制台执行，仓库提供明确步骤和 UFW 示例，不声称已经替用户修改云端状态。

- [x] 使用非 root 用户运行 Server。
  - `start_server.sh` 默认拒绝 root。
  - `docs/deployment-hardening.md` 已给出 `securechat` 用户创建、手动 daemon 和可选 systemd 部署步骤。
- [x] 提供云安全组来源 IP 收敛步骤。
  - 风险：`0.0.0.0/0` 会让全公网都能访问端口。
  - `docs/deployment-hardening.md` 已给出云安全组说明和 UFW 示例；实际云端来源 IP 需要部署者按现场网络执行。
- [x] 只开放必要端口。
  - 必要：TCP `25566`。
- [x] 明确使用 `tmux` 或 `--daemon`。
  - Server：`start_server.sh` 默认 daemon 常驻。
  - Host/Client：默认前台交互；`--daemon` 只用于显式后台运行。
  - 状态：根目录已新增 `start_server.sh`/`stop_server.sh`、`start_host.sh`/`stop_host.sh`、`start_client.sh`/`stop_client.sh`。
- [x] 移除 STUN/ICE 部署要求。
  - 当前运行模型只需要 TCP WebSocket；不再要求 UDP 候选端口或 STUN 服务器。
- [x] 提供 Nginx TLS 反向代理部署模式。
  - Nginx 在公网入口终止 TLS 并转发 WebSocket。
  - SecureChat Server 使用 `SECURECHAT_BIND_ADDRESS=127.0.0.1` 作为本机 backend。
  - 模板见 `deploy/securechat-nginx-tls.conf` 和 `deploy/securechat-server-backend.service`。
## 阶段 9：PKI 身份认证

目标：给 GKA v3 增加可验证的成员身份，防止恶意 Server 或主动中间人替换临时 X25519 public key 或伪造成员贡献。

- [x] 定义 PKI 信任根和证书用途。
  - Root CA 离线保存，只签发 Intermediate CA。
  - Intermediate CA 给 Host/Client 成员身份签名证书。
  - 成员证书只用于身份签名，Key Usage 为 `digitalSignature`。

- [x] 为 Host/Client 增加长期身份签名密钥。
  - X25519 继续只用于 ECDH、GKA contribution/state 封装和 pairwise 私发。
  - 身份签名支持 Ed25519、ECDSA-SHA256 和 RSA-SHA256。
  - 私钥只保存在本地，公钥进入成员证书。

- [x] 在 `join_room` 中绑定成员身份和临时 X25519 public key。
  - Client 对 `roomId || username || publicKey || nonce` 签名。
  - Host 验证成员证书链、有效期、Key Usage 和签名。
  - 验证通过后，Host 才信任该 Client public key 并允许其参与 GKA epoch。
  - Server 的 `room_members.memberInfos` 也携带该 signed identity；Client 会自行复验后才把成员 id/name 映射到 pairwise public key，避免单靠 Host 控制消息替换成员公钥。

- [x] 在 GKA contribution 和 `group_key`/group-state envelope 中绑定成员身份。
  - 成员对 `roomId || epoch || memberId || username || publicKey || contribution || nonce` 签名。
  - Host 对 `version || roomId || epoch || targetId || senderId || alg || kdf || ephemeralPublicKey || ciphertext || tag || nonce` 签名。
  - Client 验证 Host 证书链和签名后，才解封装 group state；随后验证每个成员 contribution 签名，再导出 group key。

- [x] 增加当前房间内证书封禁和密钥轮换机制。
  - `/evict` 和 `/ban` 会把目标成员已验证证书指纹记录在当前 Host 房间内存中，防止同一证书在本房间生命周期内重新加入。
  - 成员证书过期、Key Usage 错误或签名错误时拒绝旧证书。
  - 驱逐成员后触发 Host 发起新的 GKA epoch。

- [x] 更新 UI/CLI 和文档。
  - 显示本机身份、证书状态和验证错误。
  - Host 将 Verified 成员证书指纹通过加密 `member_identity` 控制消息同步给房间成员。
  - WinUI 成员列表默认绿色，右键切换红色 Blocked；该状态只影响本机附件自动预览，不参与 PKI 验证。
  - 明确区分房间密码、WSS 服务器证书、成员身份签名证书和 X25519 临时密钥。
  - 将 PKI 安全边界写入 README 和相关 docs，且只在实现后标记完成。

## 阶段 10：敌手测试和显式安全性验证

目标：用授权实验验证 WS/WSS、GKA v3、PKI 身份认证、encrypted relay 和附件安全边界。

- [x] 整理敌手挑战和安全测试矩阵。
  - 覆盖 WS 明文信令、WSS 抓包对比、public key 替换、Server 读取明文失败、重放/跨房间转发、坏消息 DoS、附件路径穿越、伪装附件、超大附件、恶意成员和元数据分析。
  - 文档见 `docs/adversary-challenges.md`。

- [x] 增加 Nginx TLS 反向代理测试步骤。
  - 公网只暴露 Nginx `25566`。
  - Host/Client 使用 `wss://` 完成 WebSocket upgrade。
  - Server backend 只监听 `127.0.0.1`。

- [x] 增加 Wireshark/tcpdump 抓包验证步骤。
  - WS 模式可见 WebSocket JSON 字段和房间密码。
  - WSS 模式只能看到 TLS record、证书、流量大小和时序。
  - 应用层 encrypted relay 中不应出现聊天文本、原始附件名、mime 或附件明文。

- [x] 完成本机可完成的构建和静态验证。
  - `build_win.bat` 验证 C++、WinUI 和 native core。
  - 旧 WebRTC/DataChannel/legacy 表述和旧变量残留已扫描。

- [ ] 执行公网服务器抓包实验并保存截图。
  - 需要在云服务器、客户端和 Wireshark/tcpdump 环境中手动操作。
  - 步骤和预期现象见 `docs/security-tests.md`。

- [ ] 执行 Nginx TLS 反向代理部署实验并保存截图。
  - 需要在服务器安装 Nginx 并配置证书。
  - 步骤和预期现象见 `docs/security-tests.md`。

## 阶段 11：房间治理、动态重密钥和恶意 Server 收敛

目标：在不做房间持久化的前提下，收紧 Host 管理能力、成员退出后的 GKA 轮换路径，以及恶意 Server 错误投递或伪造控制信号时的客户端行为。

- [x] 清理无实际决策作用的在线状态。
  - 移除 `RoomMember::online` 和 `RoomRegistry::markOffline`。
  - 当前房间生命周期不保留 online/offline/left/removed/expired 状态机；Host 离开即关闭房间，Client 离开即移出当前成员集。

- [x] 将 Host 本地成员移除接口改名为 `removeClient`。
  - 旧名 `removePeer` 已移除，避免与历史 DataChannel/Peer 语义混淆。
  - 收到未知或过期 `client_left` 时 Host 不轮换 group key，只记录忽略事件。

- [x] 增加 Host 管理命令。
  - `/silence <member>`：禁言目标 Client，Server 拒绝其后续 `encrypted_relay` 发送；目标仍保持连接并可接收 Host 后续重密钥。
  - `/unsilence <member>`：解除当前房间内的禁言。
  - `/evict <member>` 和 `/ban <member>`：驱逐目标 Client，并把已验证成员证书指纹加入当前房间内存封禁集。

- [x] 实现 eviction 后的证书指纹封禁。
  - Host 驱逐成员时记录其 PKI SHA-256 证书指纹。
  - 同一证书在当前房间生命周期内再次加入时，Host 拒绝并不允许其参与 GKA epoch。
  - 该封禁不跨 Host 进程或房间持久化保存。

- [x] 确认 GKA 动态密钥更新路径。
  - 新成员加入：Host 验证 PKI 后发起新的 GKA epoch，并发给当前成员。
  - Client 离开或被 Host 驱逐：Host 移除其 public key，发起新的 GKA epoch，并只发给剩余成员。
  - 禁言不改变成员资格，因此不触发 group key rotation。

- [x] 加强恶意 Server 错误投递防护。
  - Host/Client 解密 private relay 后检查 `relayTargetId`；目标不是自己时丢弃，不展示 UI。
  - 私发 relay 外层解密后还必须通过 pairwise 内层解密；没有目标成员私钥的端点无法读取私发文本或附件。
  - Host/Client 维护 relay nonce/tag replay cache；Client 对 `group_key` 检查递增 epoch，拒绝旧 key 回滚。
  - Server 伪造未知 `client_left` 不再触发 Host 重密钥。
  - Client 只把入房失败和 `host disconnected` 视为终止事件，非终止类 relay error 只提示。
  - Server 仍可造成断连或伪造已知成员离线，这属于可用性和房间状态层风险，文档中明确边界。

- [x] 更新 README、docs 和 report。
  - 管理命令、禁言/驱逐/封禁、pairwise 私发、重放防护、私发错投边界和 Host 生命周期写入文档。
  - `docs/report/report.tex` 只更新源码内容，不在本阶段编译。

## 阶段 12：贡献式 GKA 和 relay 元数据收敛

目标：让 Host 只承担开房间、关房间和发起 GKA epoch 的职责；群密钥由成员贡献集合导出。Server relay 模式下减少应用层明文元数据，私发改为广播外层 relay 加 pairwise 内层解密。

- [x] 引入 opaque room token。
  - Host/Client 本地用 `roomId + room password` 派生 room token。
  - Server 注册和路由只使用 room token；真实 roomId 留在 Host/Client 本地用于 UI 和 PKI 签名。
  - Server 进程不再需要知道人类可读 roomId 或房间密码明文。

- [x] 实现贡献式 GKA v3。
  - Host 在 room 创建、成员加入和成员离开时发起新 GKA epoch。
  - 每个当前成员生成 32-byte contribution secret，并用成员身份私钥签名。
  - Client 的 `gka_contribution` 使用 Host 的 X25519 public key 加密后交给 Server 转发。
  - Host 汇总完整贡献集合后，把 group state 用每个成员的 X25519 public key 单独封装。
  - Client 解封装 group state，逐个验证 contribution 签名，再本地导出 `K_G`。
  - Host 不再单方随机生成 room group key。
  - Host 维护 10 秒 GKA contribution watchdog；拒绝提交贡献的成员会被自动驱逐，并用剩余成员重开 epoch。

- [x] 收敛 relay 明文元数据。
  - `encrypted_relay` v3 明文字段保留 `roomId` token、`senderId` 连接 id、算法字段和 AEAD 数据。
  - 应用层 `senderName`、`senderKind` 和 `targetId` 进入加密 payload。
  - Server 不再按私发 targetId 定向转发 `encrypted_relay`，而是广播给房间内其他连接。
  - Host/Client 解密外层后检查 payload 内的 `relayTargetId`；目标不是自己时丢弃。

- [x] 私发继续使用 pairwise 内层密钥。
  - pairwise key 由发送者一次性 X25519 private key 和目标成员已验证 public key 派生。
  - Server、Host 或其他非目标成员即使收到外层 relay，也不能解开内层私发正文或附件 chunk。

- [x] 保持 Host 生命周期边界。
  - Host 关闭 WinUI、结束进程、Ctrl+C 或点击 stop session 会关闭房间。
  - Server 进程继续监听；其他房间不受该 Host 房间结束影响。
  - 当前阶段不做房间持久化。

## 阶段 13：自治安全通信协议指导原则

目标：阶段 13 开始进入课程项目完成后的长期协议演进部分，用来和前 12 个工程实现与课程收尾阶段切割。长期目标不是继续堆叠功能，而是把 SecureChat 逐步演化为 trust-minimized autonomous secure communication system。用户最终只需要信任自己的本地客户端、自己的私钥、本地策略和公开协议规则；其他成员、Host、Server、中继和网络路径都只能通过可验证证明、状态哈希链、capability、多签/阈值机制和资源预算参与系统。该阶段只定义指导思想、数学约束和验证准则，不直接实现 `entrance.scp`、Server 房间持久化或附件权限管控，避免和后续阶段重复。

- **长期自治系统目标。**
  - 系统不能消灭所有信任，只能把信任从“相信某个人或某台服务器”转为“验证数学证明、协议状态和本地策略”。
  - 用户不默认信任其他房间成员的人格、Host 的诚实、Server 的诚实或网络路径的诚实。
  - 用户本地客户端只接受满足公开协议规则的状态转移，包括签名、epoch、成员集合、GKA contribution、transcript hash、capability 和资源预算。
  - Host 最终只是拥有某类 room capability 的成员，不是不可替代的中心权威。
  - Server 最终只是可替换的 relay、状态暂存和资源调度节点，不是房间真相来源。
  - 房间状态最终由成员本地独立验证和交叉确认，而不是由某个中心节点宣布。
  - 鲁棒性目标包括 Server 被打掉后可迁移 relay、Host 掉线后不导致系统单点失效、恶意 Server 分叉投递可被发现、恶意成员刷资源会被限制。
  - 开放公网和类匿名成员是远期目标；证书只能证明某把私钥持续控制某个身份声明，不能证明现实自然人身份。

- **后续协议设计原则。**
  - 所有用户在系统全局上是平等成员；Host 只是在某个 room instance 中拥有创建和治理 capability 的成员。
  - 不引入长期全局管理员，也不假设存在所有用户共同服从的中心证书签发者。
  - 把区块链视为一组可拆分的安全技术思想，包括公开规则、本地验证、状态哈希链、分叉可发现和资源计量。
  - Server、Host 或任意单个成员都不能单方面决定其他成员必须接受的群状态；每个成员都应按公开协议规则独立验证。
  - 可信渠道只用于建立初始信任锚点，不承担日常消息投递和长期密钥分发。
  - 优先减少单点信任，而不是增加无关安全功能。
  - 能用签名、多签名、状态哈希或阈值机制解决的问题，优先不引入完整 MPC。
  - 每个新增协议字段必须说明绑定对象、重放边界和验证者。
  - 每个新增安全机制都应说明它减少了哪一种信任假设或攻击面。

- **区块链相关安全技术的应用方向。**
  - 区块链相关思想在本项目中作为独立安全技术集合使用，重点是 append-only log、hash chaining、本地验证、fork detection 和 resource accounting。
  - 早期房间以成员 PKI 作为身份绑定基础；后期公网开放场景中，系统应承认证书只能证明“某个私钥连续控制某个身份声明”，不能证明现实中的自然人身份。
  - 用户名、昵称和设备声明可能是类匿名信息，因此协议不能依赖固定真实身份或线下生物证明。
  - 每个成员本地保存自己接受过的房间状态摘要序列，例如 `T_0 -> T_1 -> T_2`。
  - 新状态必须引用上一个已接受状态摘要，形成房间内的可验证 hash chain。
  - 该机制的目标是让成员发现 Server 重放旧状态、投递不同成员集合、制造 transcript fork 或伪造管理动作。
  - 主要应用在 GKA epoch、成员集合变更、pending join、approve join、evict、ban、silence、Host rejoin、close room 和 Server open/closed 状态校验边界。
  - 对应定位是：E2EE 保护内容明文，PKI 保护身份绑定，GKA 保护群密钥协商，transcript hash chain 保护房间状态连续性，capability signature 保护管理动作授权。
  - 后续实现可引入类似结构：
    ```cpp
    struct RoomTranscriptState {
        uint64_t epoch;
        std::string roomInstanceTokenHash;
        std::string previousTranscriptHash;
        std::string memberSetHash;
        std::string contributionSetHash;
        std::string controlActionHash;
        std::string transcriptHash;
    };
    ```
  - Server 可以保存和转发状态摘要，但不能单独生成可被成员接受的状态；成员必须结合签名、Host capability、成员集合和 GKA contribution 自行验证。

- **gas-like 房间内资源计量模型。**
  - gas-like 机制在本项目中表示 room-local resource budget 或 state transition cost，用于约束房间内资源消耗和状态增长。
  - 该机制的语义是限额、节流和抗滥用，不是金钱交易、付费系统或全局账户。
  - 计量对象优先选择 Server 可验证且不要求读取应用明文的指标，例如 ciphertext bytes、attachment bytes、state transition count、GKA epoch cost、pending join count、storage lifetime 和 failed verification count。
  - 资源预算限定在 room instance 内，并绑定成员证书指纹、epoch、有效期和用途。
  - Host 最小实现可以签发预算票据；后续可升级为多签成员组或阈值机制共同签发。
  - 候选形式为 `BudgetTicket = Sign(roomAuthority, roomInstanceToken || memberFingerprint || epoch || quota || purpose || expires)`。
  - Server 只验证预算票据、剩余额度和过期时间，不需要知道消息明文、附件文件名或应用层语义。
  - 该机制可用于限制恶意成员刷附件、刷 pending join、频繁触发高成本 GKA epoch 或撑爆 Server pending 队列。
  - 资源计量应避免形成全局用户画像；预算状态优先限制在当前房间实例和当前 epoch 范围内。

- **不与 entrance 冲突的 room instance 原则。**
  - 房间名只作为人类可读输入，不作为唯一密码学身份。
  - room instance token 是具体房间实例的高熵身份；具体生成、存储和导入流程由阶段 14 定义。
  - 同名房间在不同创建实例中必须导出不同 token 和不同密钥上下文。
  - `K_G`、pairwise key、group-state wrapping key 和控制消息签名都应绑定 room instance token。
  - 附件缓存、安全日志和非明文状态文件可以使用 `hash(roomInstanceToken)` 做目录隔离；具体落地由后续附件安全和状态管理阶段定义。

- **transcript-bound GKA 原则。**
  - 每个 epoch 应维护群状态摘要 `T_e`。
  - `T_e` 绑定 room instance token、epoch、成员集合、成员贡献集合和控制动作。
  - 候选形式为 `T_e = Hash(T_{e-1} || roomInstanceToken || epoch || memberSet || contributionSet || controlAction)`。
  - GKA contribution、group state、join、leave、evict、ban、silence 等状态变化都应绑定当前 transcript。
  - Client 验证 transcript 连续性，拒绝跨房间、跨 epoch、回滚或分叉的 group state。
  - Server 即使错误投递、重放旧状态或向不同成员投递不一致状态，也应尽量被成员本地发现。

- **capability-based Host 原则。**
  - Host 权力从“当前连接身份”逐步转为“可验证的房间 owner capability”。
  - owner capability 绑定 room instance token、Host 证书指纹、权限集合、有效期和签发者。
  - `stop_session`、`approve_join`、`evict`、`ban` 等管理动作必须携带 capability 绑定签名。
  - Host 暂离、Host 重连和房间显式关闭的具体状态机由阶段 15 定义。
  - Host 重连时，成员本地验证 capability 连续性和签名，而不是只相信 Server 的连接声明。

- **阈值和多签治理边界。**
  - 阈值和多签是后续增强方向，不阻塞阶段 14 的单 Host 审批最小实现。
  - 成员证书或房间准入材料的确认可以从单点签发逐步演进为多签或阈值签名。
  - Root CA 或 Intermediate CA 私钥可评估 Shamir Secret Sharing 备份和恢复。
  - 新成员加入、Host 重入、房间所有权转移等高风险动作可要求多方签名确认。
  - 多签确认内容必须绑定 room instance token、成员证书指纹、epoch、nonce 和动作类型。
  - 先评估多签名和阈值签名，只有需要隐藏投票输入或秘密输入时再考虑完整 MPC。

- **自治协议验证用例。**
  - Server 重放旧 epoch。
  - Server 给不同成员发送不同成员集合。
  - Server 给不同成员投递不同 transcript head，制造房间状态分叉。
  - 恶意成员拒绝提交 GKA contribution。
  - 恶意成员尝试伪造 Host 管理动作。
  - 旧 Host capability 被回滚或重放。
  - 同名房间尝试复用旧 room token 或旧状态摘要。

- **文档和代码注释原则。**
  - 文档中明确“自治安全通信协议”的长期设计原则。
  - 解释 transcript、capability、threshold signature、multi-signature、secret sharing 和 MPC 的区别。
  - 代码实现时为每个协议字段补充功能性注释。

## 阶段 14：entrance.scp 房间准入容器和房间级成员 PKI

目标：用 `entrance.scp` 统一承载房间准入材料和房间级信任锚，替代用户手写 room password 和手工分发 Root/Intermediate 证书。`.scp` 表示 SecureChat PEM，是项目自定义加密准入容器后缀，不等同于标准明文 PEM。成员私钥只在成员本机生成和保存；系统不引入长期全局管理员。Host 只是某个 room instance 的创建者和当前治理角色，不是所有用户之上的中心管理者。

- [x] 定义 room instance 和文件边界。
  - `room name` 只作为用户输入和界面显示名称，不作为唯一密码学身份。
  - Host 创建房间时生成高熵 `roomInstanceId` 和至少 256-bit 的准入 secret。
  - Host 先生成房间级 Root/Intermediate/Host 密钥对，再用 canonical room name、`roomInstanceId`、准入 secret、Root 公钥指纹、Intermediate 公钥指纹和 Host 公钥指纹构造带长度前缀的 canonical 字段序列，并对该序列计算 SHA-256 派生 `roomInstanceToken`。
  - Root/Intermediate/Host 成员证书生成时把 `roomInstanceTokenDigest`、`roomInstanceId`、角色和设备名写入 X.509 subject 或扩展，避免证书内容和 token 互相依赖造成循环。
  - 同名房间在不同时间、不同 Host 或不同 Server 上创建时，必须拥有不同的 `roomInstanceToken`。
  - 项目级 `certs/` 只保存 Server TLS 证书、本地 TLS 开发 CA 或公开配置材料。
  - 房间级准入材料、成员证书、CSR 和私钥材料都放入 `logs/certs/<原始房间名>_<roomInstanceTokenDigest前8位>/`。
  - 原始房间名必须能直接作为本机文件夹名使用；包含路径分隔符、Windows 保留字符、控制字符、结尾空格或结尾点号时拒绝创建或导入。
  - 必须持久化的运行材料写入本机加密二进制 `room-state.scb`；在线主流程不生成 `room-runtime.json`、`room-descriptor.json`、`*.csr.json` 或 `*-sign-response.json` 明文中间文件。

- [x] 定义 `entrance.scp` 加密容器格式。
  - `.scp` 是 SecureChat PEM 的项目后缀，用于保存 SecureChat 自定义房间准入容器，不使用标准 PEM 明文格式保存准入材料。
  - `entrance.scp` 外层是二进制容器，只保留 magic、version、KDF 标识、AEAD 标识、KDF 参数、长度字段、salt、nonce 和 ciphertext/tag，不包含明文 room name、准入 secret、Root/Intermediate 证书或 room instance token。
  - `entrance.scp` 明文 payload 解密后包含 room name 校验信息、`roomInstanceToken` 摘要、准入 secret、Root CA 公钥证书、Intermediate CA 公钥证书、用途、版本和有效期。
  - `entrance.scp` 明文 payload 同时保存 Root/Intermediate fingerprint 和 signed room descriptor；Client 导入时必须交叉验证 payload、descriptor 和证书实际 fingerprint 一致。
  - `entrance.scp` 绝不能包含 Root CA 私钥、Intermediate CA 私钥、Host 私钥或任何成员私钥。
  - `entrance.scp` 是房间准入 bearer credential；泄露者在不知道房间短语时不能读取准入材料，但拿到文件和短语后仍可以尝试发起入房申请，因此它只负责“允许申请”，不直接授予群聊密钥。
  - `entrance.scp` 不上传 Server，Server 只接收由 Host/Client 本地派生出的 opaque room token 和连接状态。
  - `entrance.scp` 支持二维码、短码或指纹核验，便于用户通过短期可信渠道确认来源。

- [x] 定义房间短语解锁模型。
  - 房间短语通过短期安全渠道与 `entrance.scp` 分开发送，Server 不能看到房间短语明文。
  - 房间短语不是传统意义上的 trapdoor；它作为 KDF 输入，配合 `entrance.scp` 内部 salt 派生解密密钥。
  - 固定形式：`K_entrance = Argon2id(normalize(roomPhrase), salt, params)`，再用 AEAD 解密 `entrance.scp` payload。
  - KDF 固定使用 vcpkg `argon2` 提供的 Argon2id；如果当前依赖无法接入，则拒绝创建或导入 `entrance.scp`，不提供 PBKDF2 等降级 fallback。
  - Argon2id 参数写入 `entrance.scp` 二进制头部，例如 memory cost、iterations、parallelism、salt 长度、nonce 长度、tag 长度和 ciphertext 长度，便于后续调参和算法升级。
  - 默认参数目标是让合法用户本机解锁一次耗时约 200ms 到 1s，同时让离线猜测攻击为每个候选短语付出内存和时间成本。
  - `entrance.scp` 头部保留 KDF version 和 Argon2id 参数版本；实现只接受明确支持的 Argon2id version，未知 version 或非 Argon2id KDF 直接拒绝，避免静默降级。
  - AEAD 优先使用 AES-256-GCM；AAD 绑定 magic、version、KDF 参数和用途，防止跨格式或降级解析。
  - 人类随手起的房间名可能低熵，不能直接当安全密钥；程序应生成或强度检查房间短语，拒绝明显弱短语。
  - UI 可以把“显示房间名”和“解锁房间短语”合并为一个短语型名称，但代码层必须按密钥材料处理它，不能把它明文传给 Server。
  - 用户不需要手动解密 `entrance.scp`；系统根据用户填写的房间短语自动派生 `K_entrance` 并解密容器。
  - 解密失败时提示“房间名/准入文件不匹配”，不暴露更细的内部解析错误。

- [x] 实现 Host 创建房间材料。
  - Host 创建房间时只输入房间名、Server URL 和个人用户名。
  - 程序本地生成本房间的 Root CA、Intermediate CA、Host 成员私钥、Host 成员证书、Host 设备/身份声明和 signed room descriptor。
  - signed room descriptor 绑定 canonical room name、`roomInstanceId`、`roomInstanceTokenDigest`、Root/Intermediate/Host 证书指纹、公钥指纹、Host 用户名和 Host 设备名。
  - 程序导出 `logs/certs/<原始房间名>_<digest前8位>/entrance.scp`，供 Host 通过短期可信渠道分发给准备加入的成员。
  - Host 本地保存 Root/Intermediate 私钥和 Host 私钥；这些私钥只留在 Host 设备或后续定义的安全备份机制中。
  - 已实现 `cert.exe create-entrance`：生成房间级 Root/Intermediate、Host key/cert、AES-256-GCM 加密的 `entrance.scp` 和本机加密 `room-state.scb`。
  - 已实现房间级证书 schema：证书保留标准 OpenSSL/X.509 字段，并写入 `O=SecureChat`、`serialNumber=<roomInstanceTokenDigest>`、角色、设备名和 Netscape Comment。

- [x] 实现 Client 导入 entrance 和本地生成成员材料。
  - Client 加入房间时输入房间短语、Server URL 和个人用户名，并导入 `entrance.scp`。
  - 程序先用房间短语解密 `entrance.scp`，再校验容器内的 room instance 信息、有效期、用途和证书链。
  - Client 重新计算 Root/Intermediate/Host 证书指纹、公钥指纹和 `roomInstanceToken`，并确认它们与 signed room descriptor 和 `entrance.scp` payload 中的记录一致。
  - 如果攻击者把其他房间的 Root/Intermediate 证书、descriptor 或 token 混入当前 `entrance.scp`，Client 必须在导入阶段拒绝。
  - WinUI 导入时显示房间名、Root fingerprint、Intermediate fingerprint、有效期和用途，要求用户确认。
  - CLI 提供 `print-entrance-fingerprint`、`verify-entrance` 和 `import-entrance` 等操作。
  - Client 本机生成成员私钥、CSR、设备/身份声明和本房间成员证书存放目录。
  - 成员私钥生成时读取用户配置的成员私钥口令；口令为空则生成无口令私钥，口令非空则生成加密私钥。
  - 成员私钥口令只用于保护本机房间级成员私钥，不参与房间准入材料分发，也不发送给 Server、Host 或其他成员。
  - Client 只在当前流程中使用 `entrance.scp` 解出的准入 secret 派生入房 token 和准入信令加密 key；该 secret 只写入本机加密 `room-state.scb`，不写入普通长期配置。
  - 已实现 `cert.exe inspect-entrance` 和 `cert.exe import-entrance`：使用 Argon2id 解锁 `entrance.scp`，验证 descriptor 签名、证书 fingerprint 和 room instance 绑定，导出 Root/Intermediate 公钥证书，并在 Client 本机生成成员私钥和 CSR。
  - WinUI 导入流程通过文件选择器选择 `entrance.scp`，native 导入过程校验 room name、descriptor、Root/Intermediate fingerprint、有效期和用途；导入结果通过状态事件反馈。

- [x] 实现 Host 审批和签发成员证书。
  - Client 把 CSR、设备/身份声明和 entrance 绑定证明放入 admission-encrypted payload 后发给 Host，Server 只能转发密文 envelope。
  - Host 验证 CSR、成员声明、room instance 绑定、nonce 和签名后，签发房间级成员证书链。
  - Host 返回的证书签发响应必须绑定 pending join id、CSR hash、Client public key fingerprint、Client join nonce、room instance token digest、证书链 fingerprint、成员名和设备名，并通过 admission-encrypted payload 返回。
  - Client 用 `entrance.scp` 解出的 Root/Intermediate 公钥证书验证 Host 返回的成员证书链，并检查证书中的 public key 是否等于自己本机生成的 public key。
  - Client 拒绝不匹配当前 CSR、当前 nonce、当前 room instance 或当前 entrance trust anchor 的证书响应。
  - A 房间成员证书拿到 B 房间使用时，应因证书链不能追溯到 B 的 Root/Intermediate，或因证书/签发响应绑定的 room instance 不匹配而失败。
  - 最终验证链路应形成 `CA key pair -> CA public key fingerprint -> roomInstanceToken -> entrance.scp -> member certificate -> identity signature -> GKA transcript`；任一环替换为其他房间材料都必须导致后续验证失败。
  - Host 不生成 Client 私钥，也不接触 Client 私钥口令。
  - 签发记录绑定 room instance token、成员公钥指纹、成员名、设备名、证书序列号、有效期和签发者指纹。
  - 后续增强可以把 Host 单签升级为多签或阈值签名，但最小实现先由当前房间 Host 审批。
  - 已实现 `cert.exe sign-csr`：Host 使用房间级 Intermediate CA 签发 Client CSR，并输出成员证书、成员证书链和签名响应。
  - 签发响应由联机 admission-encrypted payload 返回，Client 在线验证 CSR hash、成员 public key、证书链和 room instance 绑定后自动安装成员证书链，不再鼓励落地明文签发响应文件。
  - CSR bundle 和 pending join proof 已通过 admission-encrypted payload 经 Server 在线转发，Host 审批绑定 pending join id、CSR hash、Client public key、room instance token 和签发响应。

- [x] 更新 Host/Client/WinUI 接入方式。
  - 增加 `cert.exe` 作为阶段 14 的命令行入口，负责创建、导入、核验 `entrance.scp`，生成 CSR，并辅助 Host 审批和签发房间级成员证书。
  - `cert.exe` 可以在现有 `cert_generation.cpp/.hpp` 基础上继续扩展；证书生成、证书链验证、房间级 CA、CSR 和 entrance 容器逻辑应沉入可复用核心代码，避免只写在 CLI 外壳中。
  - 已新增 `cert.exe`，并把入口容器、CSR 和成员签发逻辑放入 `cert_generation.cpp/.hpp`，CLI 只负责参数解析。
  - 已实现 Host/Client CLI `--room-dir`，由房间证书目录自动填充当前所需 PKI 环境和 room instance token，作为开发和自动化入口。
  - 已实现 native API `chat_host_start_auto` 和 `chat_join_start_auto`：WinUI 不显示 room-dir，Host 点击启动房间时自动创建 `logs/certs/<原始房间名>_<digest前8位>/entrance.scp`，Client 点击加入房间时选择 Host 分发的 `entrance.scp`。
  - 已实现 WinUI Client pending 状态：进入 pending 前不能发送消息或附件，只显示等待加入；Host 看到灰色 pending 成员卡片后可左键 approve、右键 reject。
  - 已实现 CSR 在线审批：Client 导入 entrance 后本机生成成员私钥和 CSR，CSR bundle、pending join proof 和 Host 签发响应均通过 admission-encrypted payload 传输，签发响应在线内存生成并发送，不落盘为 JSON，Client 安装响应后再参与 GKA。
  - 已清理 CLI 和 WinUI 中由用户手写的 room password 输入框；Host/Client 只通过 room-dir 读取 room instance token。
  - WinUI 和 CLI 中的 trust store、成员证书链、成员私钥显式路径在 entrance 流程落地后移除，由程序按 room instance 自动读取。
  - 成员私钥口令输入保留；该口令可以写入本地 config，避免用户每次进入房间都重复输入。
  - 如果攻击者只拿到用户的房间级成员私钥文件和公用 `entrance.scp`，没有成员私钥口令时仍不能以该用户身份登录。
  - WinUI 保留 `Local Server TLS CA / 本地服务器 TLS 信任根`，它只用于本地/局域网 WSS 服务器证书验证，与房间成员 PKI 分离。
  - Host 创建房间时 UI 检查房间名/房间短语熵；过短、常见词、纯数字或明显弱短语应给出警告或拒绝。
  - Join 界面保持“输入房间名/房间短语 + 选择 entrance.scp + 点击加入”的普通用户流程。

- [x] 更新协议接入点。
  - `create_room` 使用 `roomInstanceToken` 或其 opaque 派生值注册房间，不把 room name 或准入 secret 明文交给 Server。
  - `join_room.identity` 继续携带已签发成员证书链、nonce 和签名。
  - 首次入房的 `join_room` 使用 `admissionPayload` 字段承载加密后的 CSR bundle 和 pending join proof，不允许明文 `csrBundle` 或 `joinProof` 字段。
  - 验签内容绑定 room instance token、成员本地生成的临时 X25519 public key、成员身份公钥和设备声明。
  - 成员后续重新加入时，需要发送成员证书链并对 Server/Host 给出的新 nonce 签名，证明自己持有该证书对应私钥。
  - Server 或中间人可以重放旧证书链，但不能生成当前 nonce 的私钥签名；Client/Host 必须拒绝缺少新鲜 nonce 绑定的身份消息。
  - Server 不验证应用层成员证书；Host/Client 在本地验证证书链、签名和 room instance 绑定。
  - 已实现 room-dir 启动路径把 `roomInstanceToken` 作为 Server 路由 token；Host/Client 本地使用房间级证书签名 join、GKA contribution、group key envelope 和 room control；pending CSR 与签发响应使用 admission secret 派生密钥做额外加密。

- [x] 定义房间内拉黑、驱逐和证书轮换边界。
  - 不设计跨房间、跨会话的全局证书吊销权力。
  - 用户 A 拉黑用户 B 时，只影响用户 A 的本地接收、显示、附件预览和信任策略。
  - Host 在某个房间内驱逐成员时，只影响该 room instance 的成员资格和后续 epoch。
  - Host `/reject` pending join 时只封禁该申请对应的当前房间指纹；申请者断线取消 pending 不产生封禁。
  - Host `/evict` 或 `/ban` active 成员时封禁该 room instance 内的证书指纹，并触发后续 group key rotation。
  - 证书过期、私钥泄露或设备丢失时，通过重新签发房间证书、用户本地拉黑旧指纹和房间内移除来收敛风险。
  - 不引入默认在线查询机制，避免向 Server 或第三方暴露成员证书、房间关系和查询时间。

- [x] 补充文档和测试。
  - 已在 README 和证书文档中给出 Windows/Linux entrance 生成、导入和核验流程。
  - 已在启动文档中给出 WinUI 一键创建房间准入证书、导入 entrance 和审批 CSR 的流程。
  - 代码路径保证 Host 只接收 Client CSR、公钥、CSR 签名和 pending join proof，不接收 Client 私钥或成员私钥口令。
  - 已覆盖错误 entrance、错误 CSR、错误证书链、room instance 绑定篡改的导入/验签拒绝路径。
  - Windows 本地构建通过；阶段 14/15 的本地 WSS smoke 覆盖 Server、Alice Host、Bob Client、pending join、approve、GKA 和消息发送链路。

## 阶段 15：持久化房间、Host 显式关闭和断线恢复

目标：在阶段 14 的 `roomInstanceToken`、entrance 和房间级成员证书基础上，把房间 open/closed 状态交给 Server 维护。Host 仍拥有创建房间和显式关闭房间的权力；Host 因网络波动、进程退出、Ctrl+C 或关闭 WinUI 离线时，房间保持 open。只有 Host 发出带签名的 close room 管理动作时，Server 才关闭该 room instance。

- [x] 定义持久化房间的前置条件。
  - 阶段 15 依赖阶段 14 已定义的 `roomInstanceToken`、房间级 Host 证书和 entrance 导入流程。
  - Server 路由和持久化状态使用 opaque room instance token，不使用人类可读 room name。
  - Host 管理动作使用房间级 Host 私钥签名，并绑定 room instance token、nonce、epoch 和动作类型。
  - Client 和 Host 都在本地验证管理动作签名；Server 只保存状态和转发事件，不成为安全判断依据。

- [x] 修改 Server 房间状态模型。
  - Server 保存 room instance token、open/closed 状态、当前连接集合、Host 最近连接状态和 pending join 队列。
  - Server 不保存 entrance secret、Root/Intermediate 私钥、成员私钥、聊天明文、应用层 group key 或附件明文。
  - Server 可以保存待转发的 opaque pending join 请求，但不能解释 CSR 或成员证书语义。
  - Server 对 closed 房间拒绝新消息、新入房申请和新成员状态写入。
  - Server 需要区分 Host disconnected、Host rejoined、room closed 和 member disconnected 四类事件。
  - 已实现 Server SQLite `ServerStateStore`：默认写入 `server/state/server-state.sqlite3`，保存 open/closed room instance 状态和 pending join 原始请求，Server 重启后可恢复 open 房间标记和 pending join 队列。

- [x] 重新定义 Host 连接和关闭行为。
  - Host 建房成功后，Server 把 room instance 标记为 open。
  - Host 关闭 WinUI、Ctrl+C 或进程异常退出只表示 Host disconnected，不关闭房间。
  - Host 点击 stop session 或执行管理命令时，发送签名 `close_room`。
  - Server 收到 `close_room` 后把房间标记为 closed，并向在线成员广播关闭事件。
  - 离线成员重连时，Server 返回 room closed 状态；Host/Client 不再尝试进入该 room instance。
  - 已实现 `close_room` 信令：Host 断线时 Server 保留房间并向 Client 发送 `host_disconnected`；Host 发送 `close_room` 时 Server 广播 `room_closed` 并关闭 room instance。
  - 已新增 `HostSessionCore::closeRoom()`、CLI `/stop_session`/`/close_room`、native `chat_close_room()`；WinUI Stop Session 调用显式关闭接口，窗口关闭仍走本地停止。
  - 已实现 `close_room` 房间级 Host 证书签名，签名内容绑定动作类型、epoch、room instance token 和 payload digest。
  - 后续可补强完整 transcript 摘要和跨成员确认；当前阶段以 Host 房间级证书签名作为关闭动作的安全边界。

- [x] 设计 Host 重新加入规则。
  - Host 重新加入不走普通 Client 入群审批。
  - Host 必须提交房间级 Host 证书身份，并用该身份签名后续 group key 和 room control。
  - Server 可以做基础字段和签名格式检查，但成员本地验证才是安全边界。
  - 当前房间存在其他 active 成员时，成员本地验证 Host 重入消息并接受 Host 恢复管理权。
  - 当房间内没有其他 active 成员时，Host 凭本机房间级 Host 私钥和同一 room instance token 恢复房间管理；该私钥只保存在 Host 本机房间证书目录中。
  - 已实现基础 Host reattach：同一 room token 的 Host 在原 Host socket 断开后可重新创建连接并接管现有 room，Server 会广播最新 `room_members`。
  - Host 重新接管后会从 `room_members` 中重新验证现有 Client identity，并把验证通过的 Client 加入本地成员表以触发后续 GKA。
  - 已实现 Client 在 `room_members` 和 `group_key` 路径上验证 Host identity；同一 room instance 中 Host 公钥或证书指纹变化会被拒绝。
  - owner capability、多人成员确认和阈值 Host 重入验证属于阶段 13 长期纲领，不作为阶段 15 的当前落地前提。

- [x] 设计 pending join 和 Host 审批。
  - 新成员导入 entrance 后提交 pending join 请求，不能直接成为 active 成员。
  - Host 不在线时，Server 只保存或转发 pending join 的 opaque 请求；pending 成员不能收到当前 group key。
  - Host 在线后审批 CSR 和身份声明，签发房间成员证书，并在下一轮 membership update 中加入该成员。
  - pending 成员在成为 active 前不能读取历史 group key，也不能解密当前群聊内容。
  - 已实现 Server pending join 队列、Host `pending_join` 验证、CLI `/approve` 和 `/reject`、签名 approval/rejection、Client 验证 approval 后进入 active。
  - 已实现 CSR 通过 admission-encrypted payload 经 Server 在线转发：Client 先发送加密后的 CSR bundle 和 join proof，Host 审批后返回加密后的成员证书签发响应，Client 解密安装后进入 active。

- [x] 设计成员断线、离开和移除模型。
  - 普通 Client 关闭进程或断网只表示 connection disconnected，不自动吊销房间成员资格。
  - Host 本地把成员资格和当前连接拆开：`mClientPublicKeys`、`mClientIdentityFingerprints` 等保存房间成员身份，`mConnectedClientIds` 只保存当前在线连接。
  - Client 断线时 Host 只移除当前连接状态和未完成附件传输，不删除成员证书指纹，不自动轮换 `K_G`。
  - Client 断线发生在 GKA epoch 进行中时，Host 会从当前待贡献集合移除该连接，避免网络波动拖住房间。
  - 已批准成员用同一房间成员证书重新连接时，Host 自动批准其 rejoin，并为在线成员推进新 GKA epoch。
  - Host 显式 `/evict` 或 `/ban` 成员后，才移除成员资格、封禁当前房间内证书指纹并触发 group key rotation。

- [x] 设计 Host 不在场时的 GKA 行为。
  - Host 离线期间不推进成员集合变更，不批准 pending join，不执行 remove/ban。
  - 已经 active 且持有当前 `K_G` 的在线成员可以继续发送和接收当前 epoch 的消息。
  - Host 重新加入后，处理 pending join、leave request 和 remove/ban 队列，并在需要时发起新 epoch。
  - 新 epoch 必须绑定最新 room instance token、成员集合、控制动作和 transcript 摘要。
  - 已实现 Host 离线期间不批准 pending join；Host 重新连接后 Server 会转交积压 pending join，Host 再显式 approve/reject。

- [x] 实现本机文本消息历史。
  - Host/Client 只把本端已经成功发送或成功解密显示的 `text` message 写入本机 SQLite。
  - 本机文本历史路径为 `logs/texts/<room>_<roomInstanceTokenDigest前8位>/<systemUsername>.sqlite3`，避免同一 base username 在不同房间级身份下互相覆盖。
  - SQLite 保存 sender、actor id、display kind、正文、原始 message JSON 和 `isOwn`，WinUI 重进房间时用 `isOwn` 恢复左右气泡方向。
  - 不保存附件内容、附件元数据、status/error/log、成员私钥、Root/Intermediate 私钥、`K_G`、pairwise key、admission secret 或完整 room instance token。
  - Server 侧 SQLite 只保存 room instance open/closed 状态和 pending join 队列，不保存聊天明文、附件明文、`K_G` 或成员私钥。
  - Host/Client 的本地房间证书目录仍使用 `hash(roomInstanceToken)` 隔离房间级证书和 CSR 材料。
  - 附件接收缓存也使用 `<room>_<roomInstanceTokenDigest前8位>` 隔离；更细的附件隔离和预览控制留到阶段 16。
  - 房间 closed 后，Host/Client 只接受签名关闭事件并停止当前会话；本机历史可读取，但关闭后的房间不能继续追加新会话消息。

- [x] 设计 Server 侧最小持久化状态。
  - Server 可以评估使用 SQLite 保存 room instance token、open/closed 状态、Host 最近连接状态和 pending join 队列；Server 默认状态目录与用户端 `logs/` 分离。
  - Server SQLite 不保存聊天明文、附件明文、成员私钥、Root/Intermediate 私钥、群密钥或 entrance secret。
  - Server 重启后可恢复 open 房间的状态标记，但不能恢复自己未保存也不应保存的应用层密钥。
  - Server 持久化只服务可用性和断线恢复，不改变 Server 不可信安全边界。
  - 已实现 SQLite 持久化 open/closed 房间状态和 pending join 队列；不保存密钥或聊天明文。

- [x] 设计 room-local resource budget 接入点。
  - 资源预算从阶段 13 的指导原则落到阶段 15 的 Server 队列、pending join、状态变更和大附件中继限制。
  - 当前阶段先落地静态 room-local budget：单房间 active Client 上限、pending join 队列上限、信令帧大小上限、证书/CSR payload 上限、坏消息次数上限和 GKA contribution timeout。
  - 已增加 `maxPendingJoinsPerRoom`，防止 Host 离线时 pending join 队列无限增长。
  - 预算机制只用于限流和资源保护，不能授予跳过 PKI、GKA、Host 审批或 control 签名验证的能力。
  - `BudgetTicket`、多签预算票据和阈值签发属于阶段 13 的长期治理方向，不作为阶段 15 当前落地前提。

- [x] 更新协议消息。
  - 当前阶段增加并实现 `close_room`、`pending_join`、`approve_join`、`reject_pending_join`、`host_disconnected`、`room_closed` 等控制消息。
  - `approve_join`、`reject_pending_join` 和 `close_room` 携带 Host 房间级证书签名，绑定动作类型、epoch、room instance token 和 payload digest。
  - Client 拒绝未签名、跨房间、Host 指纹变化或 payload digest 不匹配的审批/拒绝/关闭消息。
  - 已实现 `close_room`、`pending_join`、`approve_join`、`reject_pending_join`、`host_disconnected`、`room_closed` 的基础协议接入和签名验证。
  - `leave_request`、`membership_update`、完整 transcript 摘要和控制消息分叉检测属于阶段 13 长期自治协议方向，不作为阶段 15 当前落地前提。

- [x] 增加故障和安全测试。
  - 已实现 Host 断线不关闭房间：Server 只广播 `host_disconnected`，保留 room open 状态和 pending join 队列。
  - 已实现 Server 进程停止不替 Host 标记房间 closed；房间关闭只能来自 Host 签名 `close_room`。
  - 已实现 Host 显式 stop session：发送签名 `close_room`，Server 标记 closed 并广播 `room_closed`。
  - 已实现 Host 离线期间新成员申请停留在 pending；Host 重连后 Server 转交积压 pending join。
  - 已实现 Client 对 Host 身份变化的拒绝路径：`room_members` 和 `group_key` 中 Host 公钥或证书指纹变化会导致 Client 关闭会话。
  - 已完成 Windows 构建验证；本地 WSS smoke 覆盖 Server、Alice Host、Bob Client、pending join、`/list` 查看 pending requestId、`/approve <requestId>`、GKA epoch、Bob 发消息到 Host。
  - 完整 transcript fork 检测、阈值 Host 重入和多方 capability 验证属于阶段 13 长期自治协议方向。

## 阶段 16：附件隔离和跨平台权限管控

目标：把附件处理收束为“所有 file 附件默认有风险”。来源证书只用于判断“谁发来的”，不用于证明文件安全，也不让文件获得自动打开、自动运行或解除隔离的权利。阶段 16 不做附件风险分级数据库，不做本地附件 SQLite 审计台账，不做独立附件处理进程；当前重点是安全落地、默认隔离、明确提示、预览前校验和跨平台权限标记。

- [x] 重构附件语义边界。
  - `file` 是通用任意文件附件通道，不限制扩展名或格式；接收端一律按有风险文件处理。
  - `image` 是图片语义通道，只接受 `.png`、`.jpg`、`.jpeg`、`.bmp`，并要求扩展名和文件头一致；`.jpg/.jpeg` 必须通过 JPEG header 校验。
  - `voice` 是 WinUI 本机按住录音产生的语音通道，不再是“选择本地音频文件发送”的通道。
  - CLI 取消 `/voice <path>`；音频文件如需作为文件发送，必须使用 `/file <path>`，接收端按普通文件处理。
  - WinUI Voice 模式下发送按钮显示 `Hold/按住`，按下开始录音，松开发送，取消时丢弃录音。

- [x] 增加接收附件基础隔离和本机预览控制。
  - 所有接收附件落地后都会执行 best-effort 隔离标记：Windows 写入 MotW Zone.Identifier，Linux/Unix 移除执行位。
  - 普通 `file` 附件不自动打开；图片和语音仍受 WinUI 自动预览开关、结构校验和成员预览状态限制。
  - WinUI 继续使用右键成员卡片切换 Allowed/Blocked；CLI 增加 `/trust <fingerprint-prefix>` 和 `/untrust <fingerprint-prefix>`。
  - trust/untrust 只影响图片和语音是否允许自动预览，不影响 `file` 附件打开策略，不发送给 Server，不改变成员资格或房间级 PKI。

- [x] 明确阶段 16 的依赖边界和非目标。
  - 阶段 16 使用阶段 14 的房间级成员 PKI 来标识附件来源，但不把来源可信等同于文件安全。
  - 阶段 16 不做跨房间附件信任，不做证书吊销系统，不做 mTLS 依赖，不改变 Server 不可信 relay 边界。
  - 阶段 16 不引入附件安全 SQLite。附件元数据只保存在当前消息显示和接收流程需要的内存对象中，退出后不额外保留附件审计台账。
  - 阶段 16 不实现杀毒、社区 hash 黑名单、企业 EDR、内核回调或系统级强制策略。
  - 平台权限能力不可用时必须降级为保守策略，例如只保存、不自动预览、不自动打开。

- [x] 完成统一打开策略。
  - `file` 附件默认只显示“附件已接收”和本地路径提示，不自动调用系统关联程序。
  - WinUI 附件卡片显示来源成员、附件类型、文件名和大小；普通 `file` 附件没有预览按钮，不提供自动打开入口。
  - 来源 Allowed 只降低图片/语音预览限制，不降低 `file` 附件打开提示强度。
  - 来源 Blocked 时，图片/语音也只显示附件卡片，不自动进入本地解码器。
  - CLI 和 WinUI 都通过 native core 接收附件并落地隔离；WinUI 只在图片/语音上提供本地校验后的预览。

- [x] 完成 Windows 附件落地和打开策略。
  - 为所有网络来源附件写入 MotW，也就是 `Zone.Identifier` alternate data stream。
  - 文件系统不支持 ADS 或写入失败时静默降级，不影响端到端密文附件接收。
  - 图片/语音优先走 WinUI 内置预览和现有结构校验，不自动调用外部程序。
  - `file` 附件保留 MotW；即使来源 Allowed，也不静默解除 MotW，不自动运行，不自动提权。
  - 当前系统不提供脚本/可执行文件运行入口，也不提供绕过系统安全策略的参数或快捷入口。

- [x] 完成 Linux/Unix 附件落地和打开策略。
  - 接收目录使用专用缓存目录；所有接收附件完成落地后默认不授予可执行权限。
  - 所有网络来源附件接收完成后都会 best-effort 移除 owner/group/others 执行位。
  - `file` 附件即使来源 Allowed，也不会被 SecureChat 自动改变执行权限或运行。
  - 图片/语音优先走 WinUI 内置预览和现有结构校验，不自动调用外部程序。
  - 权限管控能力不可用时，Linux 后端降级为只保存、无执行位、打开前强提示。

- [x] 完成 WinUI/CLI 交互。
  - 附件卡片显示来源成员、附件类型、文件名和大小。
  - `file` 附件卡片使用统一风险提示，不按扩展名做 A/B/C 等级。
  - WinUI 右键成员卡片和 CLI `/trust`、`/untrust` 只控制图片/语音自动预览。
  - CLI 暂不增加附件审计命令；如后续需要附件管理界面，再单独设计本地索引。

- [x] 补充测试矩阵。
  - 已完成 Windows 构建验证，覆盖 C++ core、native.dll 和 WinUI 输出。
  - 已完成 WinUI 启动/关闭烟测，确认当前关闭路径没有产生新的幽灵进程。
  - 已核对 MotW 写入、Linux/Unix 去执行位、`file` 不自动预览、图片/语音结构校验和 trust/untrust 预览控制的代码路径。
  - 后续如果增加嵌入式打开器或附件管理界面，需要重新增加跨平台实机测试矩阵。
