# SecureChat 敌手挑战设计

本文档用于实验报告中的“敌手挑战”部分。所有实验都应只在本项目的本地环境、课程实验网络或自己控制的云服务器上进行，不用于攻击第三方系统。

当前系统的安全主线是：Server 作为不可信协调者和密文 relay，Host/Client 使用 GKA v2 分发 room group key，并用 AES-256-GCM 加密文本和附件。下面的挑战用于验证这个模型能保护什么、不能保护什么。

## 挑战 1：WS 明文信令被动监听

### 攻击目标

验证 `ws://` 模式下，网络路径上的被动监听者可以看到信令明文和 relay metadata。

### 前置条件

- Server 使用 `ws://` 模式启动。
- Host 和 Client 在同一授权实验网络内连接 Server。
- 攻击者只能抓包，不篡改流量。

### 实验步骤

1. 启动 Server：
   ```bash
   ./start_server.sh --mode ws
   ```
2. Host 创建房间，Client 加入房间。
3. 在 Server 所在机器或授权网关上抓取 TCP `25566` 流量。
4. 观察 WebSocket frame 或 TCP payload 中的 JSON 字段。

### 预期现象

攻击者可以看到：

- `create_room` / `join_room`；
- roomId、username；
- 房间密码在 WS 传输中的明文；
- `encrypted_relay` envelope 的 roomId、senderId、senderName、senderKind、nonce、tag、ciphertext 长度；
- `group_key` envelope 的目标 clientId、ephemeralPublicKey、ciphertext 长度。

攻击者不应看到：

- 聊天文本明文；
- 附件文件名、mime、metadata 明文；
- 附件二进制明文；
- room group key。

### 系统缓解

- 应用层文本和附件由 AES-256-GCM 保护，Server 和被动监听者只能看到 ciphertext。
- 公网部署应使用 `wss://`，避免房间密码和信令 metadata 在网络上传输为明文。

### 报告证据

- 抓包截图或日志中出现 `join_room` 和 `encrypted_relay` JSON 字段。
- 同一抓包中无法搜索到发送的聊天文本和原始附件文件名。

## 挑战 2：WSS 下的被动监听对比

### 攻击目标

验证 `wss://` 能保护 Host/Client 到 Server 的 WebSocket 传输层，降低被动监听者读取信令和 relay metadata 的能力。

### 前置条件

- Server 使用 `wss://` 模式启动。
- Host/Client 使用与证书匹配的域名连接，例如 `wss://chat.la5te2.online:25566`。
- 攻击者只能抓包，不拥有 TLS 私钥和客户端信任根。

### 实验步骤

1. 启动 Server：
   ```bash
   ./start_server.sh --mode wss
   ```
2. Host 创建房间，Client 加入房间并发送文本和附件。
3. 抓取 TCP `25566` 流量。
4. 对比 WS 模式下的可见字段。

### 预期现象

攻击者只能看到：

- TCP 连接目标 IP 和端口；
- TLS 握手和证书相关信息；
- 连接时间、流量大小、方向和时序。

攻击者不应直接看到：

- roomId、username、room password；
- `encrypted_relay` 或 `group_key` JSON 字段；
- 应用层消息或附件明文。

### 系统缓解

- WSS 提供传输层机密性和完整性。
- 应用层 E2EE 继续保护 Server 不读消息和附件明文。

### 报告证据

- WS 与 WSS 抓包对比截图。
- WSS 抓包中只能看到 TLS 记录，不能直接还原 WebSocket JSON。

## 挑战 3：中间人 public key 替换攻击

### 攻击目标

验证当前 GKA v2 尚未绑定长期身份时，主动中间人或恶意 Server 理论上可以替换 Client public key，诱导 Host 给攻击者封装 group key。

### 攻击模型

```text
Client -- join_room(publicKey=C_pub) --> 攻击者/恶意 Server
攻击者把 C_pub 替换为 A_pub
Host 收到 new_client(publicKey=A_pub)
Host 用 A_pub 封装 room group key
攻击者用 A_priv 解开 group key
```

### 前置条件

- 使用授权实验环境。
- 攻击者能控制 Server，或能在未受 TLS 保护的 WS 路径上篡改信令。
- Host 无法通过长期身份、证书或指纹校验确认 Client public key。

### 实验步骤

1. 设计一个“恶意 Server”或信令代理，只修改 `new_client.publicKey` 字段，不修改 roomId 和 clientId。
2. Client 正常发送 `join_room`。
3. 恶意 Server 把 Client 的 public key 替换成攻击者自己的 X25519 public key 后转发给 Host。
4. Host 按协议发送 `group_key` envelope。
5. 攻击者尝试用自己的 private key 解开该 envelope。
6. 攻击者继续观察后续 `encrypted_relay`，尝试解密消息。

### 预期现象

如果 Host 没有长期身份校验，攻击者可以获得当前 room group key，并解密后续文本和附件。这个挑战说明：GKA v2 已实现密钥分发和 Server 不直接持有 group key，但还不等于完整强身份 E2EE。

### 系统缓解

当前已有缓解：

- 公网应使用可信 `wss://`，降低路径中间人篡改 public key 的风险。
- Server 不生成 group key，也不参与密钥语义。

后续应补强：

- 成员长期身份密钥；
- public key 指纹展示和人工核验；
- Host/Client 对成员身份和 key 的绑定记录；
- 证书、签名或 TOFU 机制。

### 报告证据

- 恶意替换前后的 `publicKey` 对比。
- 攻击者能否解开 `group_key` 的实验结果。
- 说明该攻击依赖主动篡改和缺少长期身份绑定，不是被动监听即可完成。

## 挑战 4：恶意 Server 读取应用明文失败

### 攻击目标

验证普通不篡改的 Server 即使转发全部 `encrypted_relay`，也不能直接读取聊天文本和附件内容。

### 前置条件

- Server 记录收到的 WebSocket JSON envelope。
- Host/Client 正常完成 GKA v2。
- Server 不持有 Host/Client 的私钥或 room group key。

### 实验步骤

1. 临时启用 Server 日志：
   ```bash
   SECURECHAT_SERVER_LOG_FILE=server.log ./start_server.sh --mode wss
   ```
2. Host/Client 发送包含明显关键词的文本，例如 `secret-message-123`。
3. 发送一个带明显文件名的附件，例如 `secret-plan.txt`。
4. 检查 Server 日志和抓包中的 relay envelope。

### 预期现象

Server 可见：

- roomId、senderId、senderName、senderKind；
- nonce、tag、ciphertext；
- 消息数量和大小。

Server 不应可见：

- `secret-message-123`；
- `secret-plan.txt`；
- 附件 mime 和内容明文。

### 系统缓解

- 文本、附件 metadata 和 binary chunk 都在成员端加密。
- Server 只做 opaque relay。

### 报告证据

- Server 日志中能看到 `encrypted_relay` 转发事件，但搜索不到文本关键词和原始附件文件名。

## 挑战 5：重放和跨房间转发尝试

### 攻击目标

验证攻击者把一个房间中的 ciphertext envelope 复制到另一个房间或伪造 sender metadata 时，接收端无法正常认证解密。

### 前置条件

- 至少两个 roomId。
- 攻击者能复制某条 `encrypted_relay` envelope。
- 攻击者不能获得 room group key。

### 实验步骤

1. 在 room A 中发送一条消息，记录 `encrypted_relay` envelope。
2. 尝试把 envelope 的 `roomId` 改成 room B 后发送。
3. 尝试把 envelope 的 `senderId` 或 `senderKind` 改成其他值后发送。
4. 观察接收端是否能解密。

### 预期现象

接收端应报解密失败或认证失败。原因是 AES-GCM AAD 绑定了 roomId、senderId 和 senderKind；Server 也会用 WebSocket 会话状态覆盖 sender metadata，降低伪造 sender 的空间。

### 系统缓解

- AEAD 认证 tag 保护 ciphertext 完整性。
- AAD 绑定 room 和 sender metadata。
- Server 绑定 relay metadata 到当前 WebSocket 会话状态。

### 报告证据

- 修改 envelope 后接收端出现认证失败。
- 原始未修改 envelope 在正确房间可正常解密。

## 挑战 6：房间密码错误和重复用户名

### 攻击目标

验证普通访问控制：错误房间密码不能加入；同一 room 中重复用户名会被拒绝。

### 前置条件

- Host 已创建房间。
- 攻击者知道 roomId，但不知道房间密码。

### 实验步骤

1. Client 使用错误密码加入。
2. Client 使用已存在的 username 加入。
3. 观察 Server/Client 返回的错误。

### 预期现象

- 错误密码返回 `invalid room password`。
- 重复用户名返回 `username already in room`。
- 失败成员不会进入 room members。

### 系统缓解

- Server 保存房间密码摘要用于访问控制。
- Server 在同一 room 内检查用户名重复。

### 报告证据

- CLI/GUI 错误提示截图。
- room members 中没有失败成员。

## 挑战 7：无效 JSON 和垃圾信令 DoS

### 攻击目标

验证公网端口面对无效 JSON、超大消息或未知字段时不会无限占用资源。

### 前置条件

- Server 运行在实验环境。
- 攻击者可以连接 Server WebSocket，但不掌握房间密码。

### 实验步骤

1. 向 Server 发送非 JSON 数据。
2. 发送字段未知的 JSON。
3. 发送超过大小预算的 JSON。
4. 连续发送多次坏消息。

### 预期现象

- Server 返回错误。
- 同一连接坏消息达到阈值后，Server 主动关闭连接。
- Server 维护线程继续输出健康状态，不影响正常房间成员通信。

### 系统缓解

- JSON 大小和深度预算。
- 每种 signaling type 的字段白名单。
- 坏消息计数和连接关闭。
- 连接超时和维护线程清理 closed socket。

### 报告证据

- Server 日志中的 bad signaling message 和 closing client。
- 正常 Host/Client 通信不受影响。

## 挑战 8：附件路径穿越和特殊文件名

### 攻击目标

验证恶意附件文件名不能写出 `logs/` 目录，也不能利用 Windows 保留名或路径分隔符覆盖特殊位置。

### 前置条件

- 攻击者是房间成员，能发送附件。
- 接收端开启附件接收。

### 实验步骤

1. 构造带路径穿越的文件名，例如 `../../evil.txt`。
2. 构造 Windows 绝对路径样式，例如 `C:\Users\target\evil.txt`。
3. 构造 Windows 保留名，例如 `CON.txt`、`NUL.txt`。
4. 发送附件并观察接收端落盘路径。

### 预期现象

- 接收文件只落在 `logs/images`、`logs/voice` 或 `logs/files`。
- 路径分隔符和非法字符被替换。
- 保留名被回退或净化。
- 不覆盖任意系统路径。

### 系统缓解

- 接收端只取文件名，不信任发送方路径。
- 文件名字符净化和长度限制。
- 固定接收目录和唯一缓存名。

### 报告证据

- 原始恶意文件名与最终保存路径对比。
- 项目目录外没有生成文件。

## 挑战 9：伪装图片/语音附件

### 攻击目标

验证把不支持文件改后缀为图片或语音时，不能轻易进入图片/语音渲染路径。

### 前置条件

- 攻击者是房间成员，能发送附件。
- 准备一个非 PNG/JPEG/BMP/WAV 内容的文件。

### 实验步骤

1. 将非图片内容改名为 `.png`、`.jpg` 或 `.bmp`。
2. 将非 WAV 内容改名为 `.wav`。
3. 通过 `/image` 或 `/voice` 发送。
4. 观察发送端或接收端校验结果。

### 预期现象

- 图片路径要求 PNG/JPEG/BMP 文件头。
- 语音路径要求 RIFF/WAVE 文件头。
- 校验失败时拒绝发送或拒绝接收。

### 系统缓解

- 扩展名白名单。
- 图片和语音文件头校验。
- 文本附件不自动执行。

### 报告证据

- 校验失败提示。
- 接收端没有把伪装文件渲染为图片或音频。

## 挑战 10：超大附件和缓存消耗

### 攻击目标

验证超大附件和大量附件不会无限消耗接收端磁盘空间。

### 前置条件

- 攻击者是房间成员，能发送附件。
- 接收端设置默认或较小的 `SECURECHAT_LOGS_MAX_BYTES`。

### 实验步骤

1. 尝试发送超过限制的图片、文本文件或 WAV。
2. 设置较小缓存上限，例如：
   ```bash
   export SECURECHAT_LOGS_MAX_BYTES=1048576
   ```
3. 连续发送多个附件，观察缓存清理行为。

### 预期现象

- 超过单文件大小限制的附件被拒绝。
- 缓存超限时，接收端清理受管理目录中最旧文件。
- 无法释放足够空间时拒绝继续接收。

### 系统缓解

- `SECURECHAT_ATTACHMENT_MAX_BYTES` 统一限制单个发送附件大小，默认 100 MB。
- `logs/` 总量上限。
- 只清理受管理附件目录，避免误删项目外文件。

### 报告证据

- 超限拒绝提示。
- 清理前后的 `logs/` 文件列表和总大小。

## 挑战 11：恶意成员和历史消息限制

### 攻击目标

说明 E2EE 不能防止合法成员读取自己加入期间的消息，也不能撤回其已经获得的历史明文。

### 前置条件

- 攻击者知道房间密码并作为合法 Client 加入。
- Host/Client 正常完成 GKA v2。

### 实验步骤

1. 恶意成员加入房间。
2. 其他成员发送文本和附件。
3. 恶意成员保存收到的明文和附件。
4. Host 让该成员离开或断开连接，触发 key rotation。
5. 剩余成员继续发送后续消息。

### 预期现象

- 恶意成员能读取加入期间收到的消息和附件。
- 离开后的 key rotation 只保护后续消息。
- 已经接收并保存的历史明文无法撤回。

### 系统缓解

- 成员离开后 Host 轮换 group key。
- 后续消息使用新的 room group key。

### 报告证据

- 成员离开前可读、离开后不再收到新 `group_key` 的对比。
- 论文中明确“合法成员设备属于信任边界”。

## 挑战 12：元数据分析

### 攻击目标

验证即使内容加密，Server 或网络观察者仍可进行一定元数据分析。

### 前置条件

- Server 可观察连接和 relay envelope。
- Host/Client 正常通信。

### 实验步骤

1. 发送短文本、长文本、小图片、大附件。
2. 记录 Server 日志或抓包中的消息数量、ciphertext 大小和时间间隔。
3. 对比不同消息类型的流量形态。

### 预期现象

攻击者不能读取内容，但可能推测：

- 哪些成员在线；
- 谁在发送；
- 消息大致大小；
- 附件传输时间；
- 通信频率和会话活跃时段。

### 系统缓解

当前系统没有隐藏元数据。README 和论文中应明确该限制。

### 报告证据

- 不同消息/附件的 ciphertext 大小和时序对比。
- “内容机密性”和“元数据隐私”分开论证。

## 建议的实验报告结构

1. 威胁模型：说明敌手能力和不在范围内的能力。
2. 攻击步骤：只描述授权实验环境中的操作。
3. 观察结果：用截图、日志或抓包证明。
4. 安全性质：说明系统阻止了什么。
5. 剩余风险：说明系统没有阻止什么，以及后续改进方向。
