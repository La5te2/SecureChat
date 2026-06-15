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

