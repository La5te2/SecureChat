# SecureChat 验收应对指南

本文档用于准备验收问答，重点是代码解释和现场改功能的思路。语法细节见 `docs/cpp-csharp-guide.md`。

## 老师问“这里的代码是什么意思”

先不要逐行翻译。按三层回答：

1. 这段代码属于哪一层：
   - Server：监听、房间注册、成员状态、密文 relay。
   - Host：创建房间、验证 Client 身份、发起 GKA epoch。
   - Client：加入房间、验证 Host 身份、收发密文。
   - secure relay：AES-GCM、X25519、HKDF。
   - identity PKI：证书、签名、验签。
   - UI：收集输入、显示状态、调用 native API。
2. 输入和输出是什么：
   - 输入可能是 UI 文本、文件路径、WebSocket JSON、证书、密文 envelope。
   - 输出可能是状态事件、加密 envelope、附件缓存路径、UI 消息气泡。
3. 为什么这样写：
   - Server 不保存聊天明文。
   - Host/Client 本地验证身份。
   - UI 不能直接跨线程改控件。
   - 附件预览需要先看来源和大小。

示例回答：

> 这段代码在 `SignalingServer::relayEncrypted`，属于 Server 加密中继层。输入是成员发来的 encrypted_relay JSON，输出是广播给房间内其他成员的密文 envelope。Server 会根据 WebSocket 连接状态重写 room token 和 senderId，但不解密 ciphertext，也不读取应用层 targetId，所以它只做中转，不参与聊天明文。

## 老师要求“现在加一个功能”

先把需求拆成四问：

1. 只是界面显示，还是要进入协议？
2. 是否需要 C# 调 C++，也就是是否要改 `native_api.h/.cpp`？
3. 是否需要 Host/Client 双方都改？
4. 是否影响 Server schema、group key、PKI 或附件缓存？

然后按位置回答：

- 新按钮、新输入框：改 `MainWindow.xaml` 和 `MainWindow.xaml.cs`。
- 新设置项：改 `MainWindow.xaml.cs` 的保存/加载配置。
- 新命令：改 Host/Client session 的 `sendLine` 或 `sendLineTo`。
- 新附件类型：改 UI 文件选择、`native_api`、Host/Client `sendAttachmentRelay`、`attachment_transfer`。
- 新信令字段：改 `signaling_server.cpp` 的 schema 和 Host/Client 解析。
- 新加密逻辑：改 `secure_relay.cpp`。
- 新身份策略：改 `identity_pki.cpp` 和 UI 成员状态显示。

现场回答模板：

> 我会先确认这个功能属于 UI、协议还是加密层。如果只是显示，改 C#；如果需要调用 C++，加 native API；如果要跨成员同步，改 Host/Client 和 Server schema；如果影响密钥或身份认证，改 secure_relay 或 identity_pki，并补对应验证。

## 最常见追问

### Server 为什么不验证成员证书？

因为 Server 的设计目标是不参与成员身份语义。Server 只做字段结构和大小检查，然后转发 identity。真正的证书链、有效期、Key Usage 和签名验证在 Host/Client 本地完成。

### Host 和 Server 的区别是什么？

Server 是常驻监听和中继进程，不是聊天成员。Host 是第一个聊天成员和房间管理者，负责创建 roomId、验证成员身份、发起 GKA epoch 和关闭房间。

### C# 为什么用 DllImport？

WinUI 是界面层，不直接实现加密和协议。`DllImport` 让 C# 调用 `native.dll` 里的 C++ core，这样桌面 UI 和 CLI 共用同一套通信逻辑。

### 为什么 UI 不能直接在 native 回调里改控件？

WinUI 控件只能在 UI 线程访问。native 回调可能来自其他线程，所以 `MainWindow.xaml.cs` 用 `DispatcherQueue.TryEnqueue` 把更新投递回 UI 线程。

### 为什么附件不默认预览未知成员？

加密只能保护传输过程，不能保证解密后的本地文件一定适合直接交给图片或音频解码器。WinUI 因此默认只显示附件卡片，用户手动信任后才按设置自动预览。

## 现场不会写 C# 时怎么稳住

先定位事件函数：

- 按钮点击通常是 `xxx_Click`。
- 设置切换通常是 `xxx_Toggled` 或 `xxx_SelectionChanged`。
- 收到 native 事件从 `OnNativeEvent` 进入，再到 `AddLine`。
- 成员列表渲染在 `RefreshParticipants`。
- 附件预览在 `TryRenderAttachment` 和 `TryCreateAttachmentPreview`。

然后说明：

> C# 这边主要是 UI 状态和事件绑定。真正协议逻辑我会优先找 native API 对应的 C++ 函数，再决定是否需要改 UI。

## 现场不会写 C++ 时怎么稳住

先定位类：

- `SignalingServer`：Server 侧。
- `HostSessionCore`：Host 侧。
- `ClientSessionCore`：Client 侧。
- `secure_relay`：加密封装。
- `identity_pki`：证书和签名。
- `attachment_transfer`：附件。

然后说明：

> 我会先看这个功能是否改变 wire protocol。如果只是本地显示，不改 C++；如果要新增消息字段，先改 schema，再改 Host/Client 两端处理，最后补 UI 调用。

## 演示流程

建议把现场演示控制在“本机 Server + WinUI Host + CLI Client”的主线里。这个组合最稳：Server 和协议链路真实运行，WinUI 能展示界面功能，CLI Client 方便快速输入命令和观察状态。公网 WSS、Nginx、Wireshark 抓包可以用报告截图说明，不建议现场临时依赖公网环境。

### 演示前准备

确认已经完成构建：

```powershell
cmd /c build_win.bat
```

确认存在这些文件：

```text
out\build\x64-release\server.exe
out\build\x64-release\host.exe
out\build\x64-release\client.exe
app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
certs\pki\root-ca.pem
certs\pki\alice-chain.pem
certs\pki\alice-key.pem
certs\pki\bob-chain.pem
certs\pki\bob-key.pem
certs\pki\candy-chain.pem
certs\pki\candy-key.pem
```

准备一个固定房间名和密码，避免现场临时想：

```text
room: demo
password: 123456
host name: alice
client name: bob
server url: ws://127.0.0.1:25566
```

演示时先说明一句：

> 这里使用本机 ws:// 是为了稳定演示。ws:// 信令本身可被抓包看到；聊天正文、附件 metadata 和附件 chunk 仍然由应用层 AES-256-GCM 端到端加密。公网部署时使用 wss:// 或 Nginx TLS 入口保护传输层。

### 主要算法介绍

正式操作前先用 2 到 3 分钟讲清楚算法关系。不要一上来讲公式，先讲“每个算法负责什么”。

总览话术：

> 系统使用 WebSocket 做连接和中继，但真正保护聊天内容的是应用层密码学。PKI 负责确认成员身份，X25519 负责生成共享秘密，HKDF 负责从共享秘密或贡献集合派生出用途明确的密钥，AES-256-GCM 负责加密和认证文本、附件 metadata 和附件 chunk。群聊使用贡献式 GKA 生成 room group key，私发在 room group key 外再加 pairwise 内层加密。

按算法拆开讲：

1. PKI 身份认证：
   - 每个成员有证书链和身份私钥。
   - 证书链证明“这个签名公钥属于 Alice/Bob/Candy”。
   - 成员私钥只在本机用来签名，不发送给 Server。
   - 加入房间时，成员签名 `roomId、username、临时 X25519 publicKey、nonce`。
   - Host/Client 验证证书链和签名，防止 Server 偷换成员 public key。
   - 代码位置：`identity_pki.cpp`。

2. X25519 密钥协商：
   - X25519 是椭圆曲线 Diffie-Hellman。
   - 一方有私钥 \(a\) 和公钥 \(A=aG\)，另一方有私钥 \(b\) 和公钥 \(B=bG\)。
   - 双方分别计算 \(aB\) 和 \(bA\)，结果相同，得到共享秘密。
   - 这个共享秘密本身不直接当聊天密钥，而是交给 HKDF 派生。
   - 代码位置：`secure_relay.cpp`、`identity_pki.cpp`。

3. HKDF 密钥派生：
   - HKDF 的作用是把共享秘密或贡献集合变成固定长度、用途明确的密钥。
   - 系统用不同 label 区分用途，例如 group state 包装密钥、room group key、pairwise 私发密钥。
   - 这样同一类底层材料不会在不同协议步骤中混用。
   - 代码位置：`secure_relay.cpp`。

4. AES-256-GCM 加密：
   - AES-256-GCM 同时提供机密性和完整性。
   - 明文输入包括文本、附件元数据和附件分片。
   - 输出包括 `ciphertext、nonce、tag`。
   - 接收端如果 tag 验证失败，会拒绝解密结果。
   - Server 只能看到 ciphertext 长度、发送时序和路由元数据，看不到聊天正文。
   - 代码位置：`secure_relay.cpp`、`attachment_transfer.cpp`。

5. 贡献式 GKA：
   - GKA 是 Group Key Agreement，也就是群组密钥协商。
   - 成员加入、离开或被驱逐时，Host 发起新的 epoch。
   - 每个在线成员提交一个签名随机 contribution。
   - Host 汇总 contribution set，但最终 \(K_G\) 由每个成员本地从同一集合派生。
   - 这样 Host 负责组织流程，但不能单方决定群聊密钥。
   - 代码位置：`host_session_core.cpp`、`client_session_core.cpp`、`secure_relay.cpp`。

6. pairwise 私发密钥：
   - 群聊消息使用 \(K_G\)。
   - 私发消息在 \(K_G\) 外再加一层目标成员 pairwise key。
   - 只有目标成员能解开内层密文，Host 和其他成员不能仅凭 \(K_G\) 看到私发正文。
   - 代码位置：`secure_relay.cpp`、`host_session_core.cpp`、`client_session_core.cpp`。

7. 重放和错投防护：
   - 每个加密 envelope 都有 nonce/tag。
   - Host/Client 缓存已处理过的 encrypted relay 标识，重复 envelope 会被丢弃。
   - 私发会检查 `relayTargetId`，错投给非目标成员时静默丢弃。
   - 代码位置：`secure_relay.cpp`、`host_session_core.cpp`、`client_session_core.cpp`。

如果老师要求一句话总结算法主线，可以说：

> PKI 先证明公钥属于谁，X25519 和 HKDF 生成或包装密钥，GKA 让多成员共同贡献群密钥，AES-256-GCM 用最终密钥加密文本和附件，pairwise key 让私发在群密钥外再多一层目标成员专属保护。

### 1. 启动本地 Server

打开第一个 PowerShell，在项目根目录运行：

```powershell
.\out\build\x64-release\server.exe 25566
```

预期现象：

- 终端显示 Server 正在 `ws://0.0.0.0:25566` 或等价地址监听。
- Server 不要求配置成员 PKI。
- 可以解释：Server 只负责监听、房间注册、连接状态和密文中继，不保存聊天明文。

如果端口被占用，换一个端口，例如 25567，并把后面 URL 改成 `ws://127.0.0.1:25567`。

### 2. 启动 WinUI 作为 Host

启动 WinUI：

```powershell
.\app\chat\bin\x64\Release\net10.0-windows10.0.19041.0\win-x64\SecureChat.exe
```

在 WinUI 右侧齿轮设置中选择成员 PKI：

```text
Trust store / 信任根: certs\pki\root-ca.pem
Identity cert chain / 成员证书链: certs\pki\alice-chain.pem
Identity private key / 成员私钥: certs\pki\alice-key.pem
Identity key passphrase / 成员私钥口令: 留空
```

回到 Host 区域填写：

```text
Room: demo
User: alice
Server URL: ws://127.0.0.1:25566
Room password: 123456
```

点击启动房间。

预期现象：

- WinUI 显示房间创建成功。
- 成员列表出现 `alice`，卡片为绿色。
- 状态中可以看到类似 `Room group key ready`。

可以解释：

> WinUI 保存的是私钥文件路径，不保存 PEM 私钥内容和私钥口令。真正读取私钥、签名和验签的是本机 C++ core。Server 收不到成员私钥。

### 3. 启动 CLI Client 作为 Bob

打开第二个 PowerShell，在项目根目录运行：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\bob-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\bob-key.pem"
$env:SECURECHAT_ROOM_PASSWORD="123456"
.\out\build\x64-release\client.exe ws://127.0.0.1:25566 demo bob
```

预期现象：

- Bob 终端显示 `Signaling connected`。
- Bob 终端显示 `PKI identity ready`。
- Bob 终端显示 `Joined room demo as bob`。
- Bob 终端显示 `Room group key ready`。
- WinUI Host 侧成员列表出现 `bob`。

可以解释：

> Bob 入房时提交证书链、临时 X25519 public key、nonce 和身份签名。Host 用信任根验证证书链，再验证签名，确认这个临时 public key 属于 Bob。

### 4. 演示群聊文本

在 WinUI 输入一条群聊消息：

```text
hello bob
```

Bob CLI 应收到 Alice 的消息。

在 Bob CLI 输入：

```text
hello alice
```

WinUI 应显示 Bob 的消息。

讲解点：

- 文本先进入应用层 JSON payload。
- payload 使用当前 room group key \(K_G\) 做 AES-256-GCM 加密。
- Server 只转发 encrypted relay，看不到正文。

### 5. 演示私发

在 WinUI 的 `To: member` 输入框填：

```text
bob
```

再发送：

```text
private hello
```

Bob CLI 应能看到私发消息。此时可以说明：

> 私发不是简单地用 room group key 标记目标成员。当前设计是在外层 room group key 保护的 encrypted relay 里，再放一层 pairwise 私发密文。目标成员之外的终端即使拿到外层 payload，也不能解开内层私发内容。

CLI 方向也可以演示：

```text
/to alice private reply
```

如果目标成员名写错，发送应失败，不会降级成群发。

### 6. 演示附件和预览策略

准备一个小图片或文本文件，例如：

```text
docs\report\images\WinUI Host 创建房间.png
README.md
```

在 WinUI 里发送图片或文件附件。

预期现象：

- Bob 能收到附件提示。
- WinUI 对图片可按设置自动预览。
- 普通文件只显示附件卡片，不直接执行。

然后右键成员列表里的 `bob`，让卡片从绿色变红，再说明：

> 绿色表示当前 UI 策略允许该成员附件自动预览；红色 Blocked 表示该成员附件只显示“附件已接收”，不自动进入本地图片或音频解码器。这个状态只在当前房间内有效。

如果现场不方便传附件，可以展示报告里的截图并说明代码位置：

- `attachment_transfer.cpp`：扩展名、文件头、大小、路径净化。
- `MainWindow.xaml.cs`：WinUI 自动预览策略和成员 Blocked 状态。

### 7. 演示成员加入后的 GKA 更新

可选启动第三个 Client Candy。打开第三个 PowerShell：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\candy-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\candy-key.pem"
$env:SECURECHAT_ROOM_PASSWORD="123456"
.\out\build\x64-release\client.exe ws://127.0.0.1:25566 demo candy
```

预期现象：

- Host 显示 Candy 加入。
- Host 重新发起 GKA epoch。
- Bob 和 Candy 都显示新的 `Room group key ready`。

讲解点：

> 成员加入会触发新的 epoch。每个成员提交签名随机 contribution，Host 汇总 contribution set，但最终 \(K_G\) 由成员本地从集合派生，Host 不能单方决定群密钥。

### 8. 演示成员离开和密钥更新

在 Bob CLI 输入：

```text
/exit
```

或直接 Ctrl+C 结束 Bob。

预期现象：

- WinUI 侧 Bob 从成员列表消失。
- Host 发起新的 GKA epoch。
- 后续消息使用新的 room group key。

讲解点：

> Client 离开后不再收到新的 group state，因此不能导出后续 room group key。这个机制用于实现离开后的前向隔离。

### 9. 演示 Host 关闭房间

在 WinUI 点击 `Stop Session`。

预期现象：

- Host 房间关闭。
- Client 连接结束。
- Server 进程本身继续监听，可以继续服务其他房间。

讲解点：

> 房间生命周期绑定在 Host 会话上。Host 显式停止、关闭窗口或进程退出都会关闭房间；Server 只是常驻中继，不因为一个房间关闭而退出。

### 10. 安全性截图展示

现场不建议重新抓包，可以展示报告里的图片：

- `WS抓包.png`：本地 ws:// 下 Wireshark 能看到 WebSocket Text 和信令字段，但聊天正文搜索不到。
- `Wireshark 抓包显示 WSS 只有 TLS record.png`：公网 wss:// 下只能看到 TLS record。
- `nmap扫描测试.png`：端口暴露面验证。
- `PKI 证书错误导致成员加入失败.png`：证书错误时加入失败。

讲解顺序：

1. ws:// 说明应用层 E2EE：信令可见，聊天正文仍是 AES-GCM ciphertext。
2. wss:// 说明传输层 TLS：连 WebSocket JSON 也被 TLS 包住。
3. PKI 错误图说明身份和临时 X25519 public key 绑定，不接受被替换的公钥。
4. nmap 图说明公网只暴露预期端口，后端端口可只绑定 127.0.0.1。

### 11. 如果现场出问题的兜底路线

如果 WinUI 没启动或 UI 状态异常，直接切到 CLI 三窗口演示。

窗口 1：

```powershell
.\out\build\x64-release\server.exe 25566
```

窗口 2：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
$env:SECURECHAT_ROOM_PASSWORD="123456"
.\out\build\x64-release\host.exe --server ws://127.0.0.1:25566 demo alice
```

窗口 3：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\bob-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\bob-key.pem"
$env:SECURECHAT_ROOM_PASSWORD="123456"
.\out\build\x64-release\client.exe ws://127.0.0.1:25566 demo bob
```

CLI 能演示：

```text
hello
/to alice private hello
/image <path>
/file <path>
/voice <path>
/exit
```

如果 PKI 报错，优先检查三件事：

1. `SECURECHAT_PKI_TRUST_STORE` 是否是 `certs\pki\root-ca.pem`。
2. 当前成员的 chain/key 是否匹配，例如 Alice 用 `alice-chain.pem` 和 `alice-key.pem`。
3. PowerShell 当前目录是否在项目根目录。

如果 Client 加入后卡在等待 group key，优先确认 Host 是否还在线、房间密码是否一致、Server/Host/Client 是否同一次构建产物。

### 12. 结束时的总结话术

可以用这段收尾：

> 这个系统满足安全双向通信工具的核心要求。Server 提供监听、房间注册和密文中继；Host 和 Client 作为聊天成员通过 PKI 认证身份，通过 X25519、HKDF 和贡献式 GKA 得到 room group key；文本和附件使用 AES-256-GCM 在应用层加密。Server 和网络旁路不能读取聊天正文和附件内容。系统仍暴露必要元数据，例如连接时序和密文长度；附件解密后的本地预览也需要 UI 安全策略约束。这些边界在报告中已经作为当前限制和改进方向说明。
