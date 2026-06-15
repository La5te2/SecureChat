# SecureChat C++ / C# 语法和读代码速查

本文档用于验收前快速读懂项目代码。目标不是系统学习 C++ 或 C#，而是看到老师指的一段代码时，能说出“这段代码在做什么、为什么这样写、如果要加功能应该改哪里”。

## 先记住项目分层

SecureChat 主要分成三层：

1. C++ native core：
   - `SignalingServer`：监听端口、注册房间、维护成员连接状态、转发密文。
   - `HostSessionCore`：创建房间，是第一个成员，验证 Client 身份，发起 GKA epoch 并转发 group state。
   - `ClientSessionCore`：加入房间，验证 Host 身份，提交 GKA contribution，解封装 group state，发送/接收密文。
   - `secure_relay`：AES-GCM、X25519、HKDF、GKA contribution/state 封装，以及 pairwise 私发内层加密。
   - `identity_pki`：加载证书、验证证书链、签名和验签。
   - `attachment_transfer`：附件大小、文件名、分片、接收缓存。
2. C API bridge：
   - `native_api.h/.cpp` 把 C++ core 包成 C ABI 函数，例如 `chat_host_start`、`chat_send_line`。
   - WinUI 通过这些函数调用 C++。
3. C# UI：
   - `app/chat` 是 WinUI 桌面界面。
   - UI 层主要收集输入、显示消息、调用 native API；加密和协议不在 C# 里实现。

验收时如果被问“这个项目怎么跑起来”，按这个顺序答：Server 先监听，Host 通过 Server 创建房间，Client 加入房间，Host/Client 通过 PKI 验证身份并执行贡献式 GKA，之后群聊文本和附件用 group key 加密后由 Server 加密中继转发；私发会在外层加密中继消息内再加一层 pairwise 密钥。

## C++ 语法速查

### 头文件和源文件

`.hpp/.h` 通常写“声明”，`.cpp` 写“实现”。

```cpp
// .hpp
class HostSessionCore {
public:
    void start();
};

// .cpp
void HostSessionCore::start() {
    // 具体逻辑
}
```

验收回答：

> 头文件告诉其他文件有哪些类和函数可以调用，源文件写这些函数具体怎么做。

### include 和 namespace

```cpp
#include "secure_relay.hpp"

namespace chat::secure_relay {
    // 函数属于 chat::secure_relay 命名空间
}
```

`#include` 是引入声明。`namespace` 是给函数/类分组，避免名字冲突。

看到 `chat::secure_relay::encryptMessageWithGroupKey`，可以读作：

> 调用 `chat` 项目里 `secure_relay` 模块的 `encryptMessageWithGroupKey` 函数。

### class、public、private

```cpp
class ClientSessionCore {
public:
    void start();

private:
    std::string mRoomId;
};
```

`public` 是外部可调用接口，`private` 是类内部状态或辅助函数。

验收回答：

> public 是这个对象对外暴露的能力；private 是内部实现细节，外部不能直接改，避免状态被乱改。

### 构造函数和析构函数

```cpp
HostSessionCore::HostSessionCore(std::string wsUrl, std::string roomId)
    : mWsUrl(std::move(wsUrl)),
      mRoomId(std::move(roomId)) {
}

HostSessionCore::~HostSessionCore() = default;
```

构造函数负责初始化对象。冒号后面是成员初始化列表。`std::move` 表示把字符串内容移动进成员变量，减少拷贝。

析构函数在对象销毁时调用。`= default` 表示使用编译器默认行为。

### 智能指针

项目常见：

```cpp
std::shared_ptr<rtc::WebSocket> ws;
std::unique_ptr<rtc::WebSocketServer> server;
```

`shared_ptr` 表示多个地方可以共同持有对象。最后一个持有者消失时对象释放。

`unique_ptr` 表示只有一个所有者。适合 Server 这种明确归一个对象管理的资源。

验收回答：

> 这里用智能指针是为了让 WebSocket/Server 资源自动释放，避免手动 new/delete 引起内存泄漏。

### lambda 回调

```cpp
mWs->onMessage([this](rtc::message_variant data) {
    handleSignalingMessage(rtcMessageToString(data));
});
```

`[]` 是 lambda 捕获列表。`[this]` 表示这个回调可以访问当前对象成员。

验收回答：

> WebSocket 收到消息时会调用这个回调；回调里把底层消息转成字符串，再交给会话对象处理。

### mutex 和 lock_guard

```cpp
{
    std::lock_guard<std::mutex> lock(mMutex);
    mRooms[roomId] = Room{};
}
```

`mutex` 用于多线程保护共享数据。`lock_guard` 创建时加锁，离开作用域自动解锁。

验收回答：

> Server 可能同时处理多个 WebSocket 回调，所以修改房间表、成员表时需要加锁，避免并发读写出错。

### try / catch 和异常

```cpp
try {
    auto data = json::parse(payload);
} catch (const std::exception& e) {
    recordBadMessage(key, e.what());
}
```

`throw std::runtime_error(...)` 抛出错误，`catch` 捕获错误。

验收回答：

> 网络输入可能格式错误，所以解析失败不能让进程崩溃，而是记录坏消息并拒绝或断开异常连接。

### vector、array、unordered_map

```cpp
std::vector<unsigned char> groupKey;
std::array<unsigned char, 32> key;
std::unordered_map<std::string, Room> mRooms;
```

`vector` 是动态数组，大小可变。`array` 是固定长度数组。`unordered_map` 是哈希表，用 key 快速查 value。

项目里：

- `mRooms`：roomId 到房间状态。
- `mClients`：WebSocket 指针到连接状态。
- `mGroupKey`：当前房间对称密钥字节。

### const 引用

```cpp
void sendLine(const std::string& line);
```

`const std::string&` 表示只读引用，不复制大对象，也不允许函数修改它。

验收回答：

> 这里用 const 引用是为了减少字符串拷贝，同时保证函数不会修改传入参数。

### JSON

项目使用 `nlohmann::json`：

```cpp
json message = {
    {"type", "join_room"},
    {"roomId", roomId}
};

auto type = message.value("type", "");
```

`json` 可以像对象一样放键值。`value("type", "")` 表示取 `type` 字段，没有就返回默认空字符串。

### AES-GCM / X25519 / HKDF 在代码里怎么看

在 `secure_relay.cpp` 中：

- `generateGroupContribution()` 生成成员在一个 GKA epoch 里的随机贡献。
- `deriveGroupKeyFromContributions()` 从已验证贡献集合导出房间对称密钥 `K_G`。
- `encryptMessageWithGroupKey()` 用 `K_G` 加密群聊文本/附件 metadata/chunk，以及私发的外层 relay。
- `encryptMessageForPairwise()` / `decryptMessageFromPairwise()` 用发送者临时 X25519 key 和目标成员已验证 public key 派生 pairwise key，保护私发内层正文或附件 chunk。
- `generateMemberKeyPair()` 生成临时 X25519 密钥对。
- `encryptGkaContributionForHost()` 用 Host 的 X25519 public key 封装 Client contribution。
- `encryptGroupStateForMember()` / `decryptGroupStateForMember()` 用目标成员 X25519 key 封装/解封装完整贡献集合。

验收回答：

> 群聊内容用 room group key 加密；这个 group key 从成员签名贡献集合导出，贡献集合再用 X25519 派生出的包装密钥发给每个成员。私发还会额外派生 pairwise key。Server 只转发 JSON envelope，不知道 group key 或 pairwise key。

## C# 语法速查

### 文件结构

C# 文件通常是：

```csharp
using Microsoft.UI.Xaml;

namespace chat;

public sealed partial class MainWindow : Window
{
}
```

`using` 引入命名空间。`namespace` 表示代码分组。`class MainWindow : Window` 表示 MainWindow 继承 WinUI 的 Window。

### partial class

```csharp
public sealed partial class MainWindow : Window
```

`partial` 表示这个类分散在多个文件中。WinUI 的 XAML 会生成另一部分代码，所以 `.xaml` 和 `.xaml.cs` 合在一起才是完整窗口类。

验收回答：

> XAML 写界面布局，xaml.cs 写按钮点击和事件逻辑，partial 让它们组成同一个类。

### private readonly

```csharp
private readonly HashSet<string> participants = new(StringComparer.OrdinalIgnoreCase);
```

`private` 表示只在类内部使用。`readonly` 表示字段只能在构造阶段赋值，之后不能换成另一个集合，但集合内容仍可增删。

### record

```csharp
private sealed record VerifiedMemberInfo(string DisplayName, string Fingerprint, string Subject);
```

`record` 适合保存不可变数据，写起来比 class 简短。这里用来保存成员显示名、证书指纹和证书主题。

### enum

```csharp
private enum AttachmentMemberState {
    Allowed,
    Blocked
}
```

`enum` 是固定几个状态。这里表示附件预览策略：

- `Allowed`：默认状态，成员卡片为绿色，可按图片/音频开关自动预览。
- `Blocked`：用户在当前房间右键阻止，成员卡片为红色，不自动预览。

### 事件处理函数

```csharp
private void Host_Click(object sender, RoutedEventArgs e)
{
    // 点击 Host 按钮时执行
}
```

WinUI 按钮点击、下拉框切换、开关切换都会调用类似函数。

验收回答：

> 这个函数是 UI 事件入口。用户点击按钮后，C# 收集输入框内容，再调用 native API。

### async / await

```csharp
private async Task SendPickedFileAsync(FileKind kind)
{
    var file = await PickFileAsync(kind);
}
```

`async` 表示函数内部可以等待异步操作。`await` 等文件选择器、文件读写或 UI 动画完成，同时不阻塞界面线程。

### switch 表达式

```csharp
return kind switch
{
    "image" => "Image",
    "voice" => "Audio",
    _ => "File"
};
```

这是简短的多分支判断。`_` 是默认分支。

### null 检查

```csharp
if (file is null) return;
```

`is null` 是 C# 常见空值判断。文件选择器取消时会返回 null。

### DllImport / PInvoke

```csharp
[DllImport("native.dll", CallingConvention = CallingConvention.StdCall)]
internal static extern int chat_send_line(string line);
```

这表示 C# 调用 `native.dll` 里的 C 函数。`extern` 表示函数实现不在 C#，在外部 DLL。

验收回答：

> UI 不直接实现协议和加密，而是通过 P/Invoke 调用 C++ native core。这样 WinUI 和 CLI 可以共用同一套 C++ 通信逻辑。

### DispatcherQueue

```csharp
dispatcherQueue.TryEnqueue(() =>
{
    AddLine(kind, message);
});
```

C++ 回调可能来自非 UI 线程。WinUI 控件只能在 UI 线程修改，所以要用 `DispatcherQueue` 把 UI 更新投递回主线程。

验收回答：

> 这是为了线程安全。native 回调不能直接改 WinUI 控件，必须切回 UI 线程。

### HashSet 和 Dictionary

```csharp
HashSet<string> participants;
Dictionary<string, VerifiedMemberInfo> verifiedAttachmentMembers;
```

`HashSet` 保存不重复元素。`Dictionary` 是键值表。

项目里：

- `participants`：成员列表显示快照。
- `blockedAttachmentMembers`：当前房间右键阻止自动预览的成员。
- `verifiedAttachmentMembers`：PKI 验证通过的成员指纹信息。

## 老师问“这里的代码是什么意思”时怎么答

使用三句话模板：

1. 这段代码属于哪一层：
   - Server / Host / Client / secure relay（安全中继）/ PKI / attachment / WinUI。
2. 输入和输出是什么：
   - 例如输入 WebSocket JSON，输出转发 envelope；输入文件路径，输出加密附件 chunk。
3. 为什么这样做：
   - 例如避免 Server 看明文、避免 UI 线程被阻塞、避免未知附件自动预览。

例子：

> 这段在 `relayEncrypted`，属于 Server 加密中继层。输入是成员发来的 encrypted_relay JSON，输出是广播给房间内其他成员的同一个密文 envelope。Server 会绑定 room token 和 senderId，但不会读取 senderName、targetId 或 ciphertext，这样 Server 只做中转，不参与聊天明文。

## 老师要求现场加一个功能时怎么拆

先不要直接写代码，先拆成四问：

1. 这个功能是 UI 功能、协议功能、还是加密功能？
2. 是否需要改 native C API？
3. 是否需要改 Server 转发字段？
4. 是否需要改 Host/Client 两边逻辑？

常见位置：

- 新按钮/输入框：改 `MainWindow.xaml` 和 `MainWindow.xaml.cs`。
- 新 UI 设置：改 `MainWindow.xaml.cs` 的配置保存/加载。
- 新发送类型：改 WinUI 调用、`native_api`、Host/Client session、attachment 或 secure relay。
- 新信令字段：改 `common.hpp` 的 Message/协议限制、`signaling_server.cpp` 的 schema、Host/Client 处理。
- 新加密策略：改 `secure_relay.cpp`，再同步 Host/Client 调用。
- 新身份策略：改 `identity_pki.cpp`，再同步 UI 显示。

现场回答可以说：

> 我会先确认这个功能属于 UI、协议还是加密层。如果只是界面显示，改 C#；如果需要传给 C++，还要加 native_api；如果要跨成员同步，需要改 Host/Client 和 Server schema；如果影响密钥或身份验证，需要改 secure_relay 或 identity_pki，并补对应测试。

## 最容易被问的几个代码点

### Server 为什么不验证成员证书？

因为 Server 的设计目标是不可信 relay。Server 只检查 `identity` 字段结构和大小，避免旧客户端或畸形消息进入协议；证书链、有效期、Key Usage 和签名由 Host/Client 在本地验证。这样 Server 不需要参与成员身份语义。

### 为什么 Host 是第一个成员，不是 Server？

Server 是监听和中继进程，不发聊天消息、不持有 group key。Host 是创建 room 的第一个聊天成员，负责管理房间生命周期并发起 GKA epoch。

### 为什么 UI 点击成员复制指纹？

界面只显示成员名，避免长 id 或指纹撑坏布局。完整指纹用于人工核对身份，所以点击成员框复制。

### 为什么成员可以右键 Block？

图片和音频解码器也是攻击面。即使内容传输有加密，解密后的本地文件仍可能是恶意构造文件。WinUI 默认允许成员自动预览以简化演示；用户右键成员卡片后，该成员变为 Blocked，不再自动进入图片或音频解码器。

### 为什么普通文件不预览？

普通文件格式太多，打开时可能调用系统关联程序。项目只在界面内有限预览图片和 WAV，普通文件只显示附件卡片和路径。

### 为什么 close 要异步 shutdown？

native WebSocket 关闭可能等待网络资源释放。如果 UI 线程直接等待，会出现窗口关闭延迟。WinUI 里用后台 Task 调用 `chat_shutdown`，并设置兜底退出。
