# SecureChat 敌手挑战设计

本文档用于设计和记录 SecureChat 的授权安全测试。所有测试都应只在本项目的本地环境、受控实验网络或自己控制的云服务器上进行，不用于攻击第三方系统。

当前系统的安全主线是：Server 作为不可信协调者和密文 relay，Host/Client 使用 GKA v2 分发 room group key，并用 AES-256-GCM 加密文本和附件。下面的挑战用于验证这个模型能保护什么、不能保护什么。

从安装、构建、启动到基础功能验收的主流程见 `README.md` 的“完整测试流程”；本文档只展开敌手挑战的攻击步骤、预期现象和留证方式。

## 测试范围

### 威胁模型

- 局域网被动监听者：可能观察 `ws://` 明文信令和流量元数据。
- 局域网主动攻击者：可能篡改未受 TLS 保护的信令，尝试 public key 替换、identity 替换或连接干扰。
- 公网扫描者：可能探测 TCP `25566`，触发无效连接或弱密码尝试。
- 恶意房间成员：加入后可读取当前 group key 下的群消息和附件。
- 被攻破的不可信 Server：可观察 room、sender、时序和 ciphertext 大小，但不应获得 room group key 或应用明文。
- 恶意附件发送者：可能发送伪装文件、超大文件、特殊文件名或诱导用户手动打开附件。

### 安全目标映射

- 机密性：文本和附件 metadata/chunk 使用应用层 AES-256-GCM encrypted relay；Server 只转发 ciphertext。
- 完整性：文本和附件 metadata/chunk 使用 AES-256-GCM AEAD；room/sender metadata 由 Server 绑定到 WebSocket 会话状态。
- 密钥协商：GKA v2 使用临时 X25519 public key、Host 分发 room group key、成员加入/离开后 key rotation。
- 认证与访问控制：房间密码限制加入；WSS 提供 Server 证书校验；可选 mTLS 反向代理限制客户端连接准入；PKI 成员身份认证强制把成员证书签名绑定到 `join_room` public key 和 `group_key` envelope。
- 附件安全：大小限制、扩展名白名单、图片/语音文件头校验、文件名净化、固定缓存目录、缓存总量限制、不自动执行，WinUI 未知成员附件默认不自动预览。
- 可用性：连接数和坏消息限制、连接超时、维护线程清理、daemon 脚本、可选 systemd 模板。
- 部署卫生：默认不落盘日志、非 root guard、必要端口说明、安全组来源 IP 收敛步骤。
- 隐私：GUI/Web 不显示底层 endpoint/log 噪声；Server 仍可见元数据。

### 已知限制

- `ws://` 信令明文；公网应使用 `wss://`。
- 恶意或被攻破 Server 仍可尝试 public key 替换攻击，但应被 PKI 签名绑定检测出来。
- 成员退出后的 key rotation 只保护后续消息，不能撤回该成员曾持有 key 时可读的历史消息。
- Server 仍可观察 room、sender、连接时间、ciphertext 大小、消息数量和转发时序等元数据。
- 当前私发是 group key 下的定向投递，不提供独立私聊密钥隔离。
- 附件校验不是杀毒；没有沙箱、恶意文件扫描、复杂文档格式解析隔离或用户手动打开保护。
- 接收端本机会留下解密后的附件缓存，成员设备被攻破时 E2EE 无法保护本机明文。

### 基础测试矩阵

- 局域网 Server + Host + Client 文本收发。
- 局域网图片、语音、文本文件附件收发。
- 公网 Server + 群主 Host + Client 加入。
- Server encrypted relay 下文本和附件收发，确认 Server 日志不含应用明文。
- 私发文本和私发附件只投递给目标成员。
- 错误房间密码拒绝。
- 重复用户名拒绝。
- 不支持附件类型拒绝。
- 超过大小限制的附件拒绝。
- 伪装图片/语音文件头拒绝。
- 特殊文件名和路径穿越附件名净化。
- 附件缓存超限清理或拒绝。
- 成员加入后收到 `group_key` 并可以发送消息。
- 成员离开后 Host 轮换 group key，剩余成员继续通信。
- 当前强制 PKI 下，无 `identity` 的 Client 被 Server/Host 拒绝。
- 当前强制 PKI 下，篡改 `join_room.publicKey` 或 `identity.signature` 会被 Host 拒绝。
- 当前强制 PKI 下，篡改 `group_key.ciphertext`、`ephemeralPublicKey` 或 `identity.signature` 会被 Client 拒绝。
- 当前强制 PKI 下，证书链中任一证书指纹进入 `SECURECHAT_PKI_REVOCATION_FILE` 时身份被拒绝。
- 启用 mTLS 反向代理后，无客户端证书连接被 Nginx 拒绝，有受信任客户端证书连接成功。
- Host 断开后 room 关闭，Client 收到停止提示。
- Server stop/SIGTERM 后释放 TCP `25566`。

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

### 验证证据

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

### 验证证据

- WS 与 WSS 抓包对比截图。
- WSS 抓包中只能看到 TLS 记录，不能直接还原 WebSocket JSON。

## 挑战 3：中间人 public key 替换攻击

### 攻击目标

验证主动中间人或恶意 Server 替换 Client public key 时，Host 会因为 `join_room` identity 签名覆盖的 public key 不一致而拒绝该成员。

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
- Host 和 Client 均配置 `SECURECHAT_PKI_TRUST_STORE`、`SECURECHAT_IDENTITY_CERT_FILE` 和 `SECURECHAT_IDENTITY_KEY_FILE`。

### 实验步骤

1. 设计一个“恶意 Server”或信令代理，只修改 `new_client.publicKey` 字段，不修改 roomId、clientId 和原始 `identity`。
2. Client 正常发送 `join_room`。
3. 恶意 Server 把 Client 的 public key 替换成攻击者自己的 X25519 public key 后转发给 Host。
4. Host 验证 `identity`。
5. 攻击者尝试让 Host 继续发送 `group_key` envelope。

### 预期现象

Host 验证 `join_room` identity 时会发现签名覆盖的 public key 与被替换后的 public key 不一致，拒绝该 Client，并通过 `reject_client` 让 Server 移除连接。若攻击者改动 `group_key` envelope，Client 会在解封装前验证 Host identity 失败。

### 系统缓解

当前已有缓解：

- 公网应使用可信 `wss://`，降低路径中间人篡改 public key 的风险。
- Server 不生成 group key，也不参与密钥语义。
- 成员身份签名绑定 `join_room` public key，Host 身份签名绑定 `group_key` envelope。

当前不覆盖：

- 成员设备被攻破后的本地私钥泄露；
- 已被 CA 签发且未被吊销的恶意成员证书；
- 接收成员拿到明文后的截图、复制或二次转发。

### 验证证据

- 恶意替换前后的 `publicKey` 对比。
- Host/Client 的 identity verification failed 或 reject_client 记录。
- 说明该攻击依赖主动篡改；当前强制 PKI 应阻止静默 public key 替换。

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

### 验证证据

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

### 验证证据

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

### 验证证据

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

### 验证证据

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

### 验证证据

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

### 验证证据

- 校验失败提示。
- 接收端没有把伪装文件渲染为图片或音频。
- WinUI 中攻击者不是 PKI Verified 成员，或虽 Verified 但未被当前房间临时标记为 Trusted 时，图片/音频只显示附件卡片，不自动进入图片或音频解码器。

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

### 验证证据

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

### 验证证据

- 成员离开前可读、离开后不再收到新 `group_key` 的对比。
- 测试记录中明确“合法成员设备属于信任边界”。

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

当前系统没有隐藏元数据。测试记录应明确该限制。

### 验证证据

- 不同消息/附件的 ciphertext 大小和时序对比。
- “内容机密性”和“元数据隐私”分开论证。

## 挑战 13：端口扫描和 TCP 半连接耗尽

### 攻击目标

验证公网部署只暴露必要端口，并说明 TCP 半连接耗尽属于可用性和部署安全问题，不属于 E2EE 密码学问题。

### 前置条件

- 只在本机、实验局域网或自己控制的云服务器上测试。
- 云安全组、系统防火墙和 Nginx/Server 日志可观察。
- 若测试 TCP SYN 半连接，使用低速、限量请求，不对第三方公网地址执行。

### 实验步骤：端口扫描

1. 在云服务器上启动 SecureChat Server 或 mTLS 反向代理入口。
2. 从授权测试机扫描预期端口：
   ```bash
   nmap -Pn -p 22,80,443,25566,25567,5188 <your-server-ip-or-domain>
   ```
3. 对比云安全组和本机监听：
   ```bash
   ss -lntp
   sudo ufw status
   ```
4. 如果使用 mTLS 反向代理，确认公网只暴露 Nginx 的 `25566`，后端 `25567` 只监听 `127.0.0.1`。

### 预期现象：端口扫描

- 普通公网聊天入口只应暴露 `25566`。
- Web UI `5188` 不应直接暴露公网。
- mTLS 部署中，公网应看到 Nginx `25566`，不应直接访问后端 `25567`。
- Server 进程不是群成员，端口扫描只能证明服务暴露面，不能读取聊天明文。

### 实验步骤：TCP 半连接

1. 在云服务器上查看系统 SYN 防护状态：
   ```bash
   sysctl net.ipv4.tcp_syncookies
   ss -ant state syn-recv
   ```
2. 在授权测试机上进行低速、限量 SYN 测试，例如使用 `nping`：
   ```bash
   sudo nping --tcp -S -p 25566 --rate 10 -c 100 <your-server-ip-or-domain>
   ```
3. 测试期间在服务器上观察半开连接数量：
   ```bash
   watch -n 1 "ss -ant state syn-recv | wc -l"
   ```
4. 观察 SecureChat Server 是否仍能接受正常 Host/Client 连接。

### 预期现象：TCP 半连接

- 低速、限量 SYN 测试不应导致 Server 长时间不可用。
- 半连接防护主要由 Linux TCP 栈、SYN cookies、云安全组、反向代理和连接 backlog 处理。
- SecureChat 应用层的连接超时、连接数限制、坏消息限制和维护清理只能处理 WebSocket 建立之后的资源消耗，不能单独抵抗高强度 SYN flood。

### 系统缓解

- 云安全组限制来源 IP 或来源 CIDR。
- 公网部署优先使用 Nginx/mTLS 入口，由反向代理承接 TLS 和连接准入。
- Linux 开启 SYN cookies，并使用云厂商 DDoS/安全组能力。
- SecureChat Server 保持 `connectionTimeout`、连接数限制、坏消息限制和维护线程清理。

### 验证证据

- `nmap` 扫描结果。
- `ss -lntp`、`ufw status`、云安全组截图。
- `ss -ant state syn-recv` 在测试前后的数量变化。
- 正常 Host/Client 在测试期间能否连接和发送消息。

## 建议的测试记录结构

1. 威胁模型：说明敌手能力和不在范围内的能力。
2. 攻击步骤：只描述授权实验环境中的操作。
3. 观察结果：用截图、日志或抓包证明。
4. 安全性质：说明系统阻止了什么。
5. 剩余风险：说明系统没有阻止什么。
