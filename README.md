# SecureChat

SecureChat 是一个双向通信实验项目，包含共享 C++ 核心、Windows WinUI 桌面端、命令行 Host/Client 工具，以及跨平台 ASP.NET Core Web UI。

## 组件

- `src/` 和 `include/`：C++ 信令服务器、WebSocket encrypted relay 数据通路、附件传输、CLI 和 native API。
- `app/chat/`：Windows WinUI 桌面客户端。
- `app/web/`：Windows/Linux 可用的 ASP.NET Core Web UI。
- `build.bat`：Windows 上只构建 C++。
- `build_win.bat`：Windows 上构建 C++ 和 WinUI。
- `build_web.bat`：Windows 上构建 C++ 和 Web UI。
- `build.sh`：Linux 上（云服务器）只构建 C++。
- `build_web.sh`：Linux 上（非云服务器）构建 C++ 和 Web UI。

说明：项目依赖 libdatachannel 的 WebSocket/WebSocketServer 实现；聊天数据通路是 WebSocket encrypted relay。

## 安全说明

SecureChat 当前定位为课程/论文实验系统；公网运行时应按本节安全边界和部署约束使用。

公网 Server 常开时，主要暴露面是：

- TCP `25566`：WebSocket 信令和 opaque encrypted relay 端口，用于创建/加入房间、维护成员状态，以及转发密文 envelope。

需要明确：

- 信令支持 `ws://` insecure mode 和 `wss://` secure mode。`ws://` 配置简单、便于本地或无证书场景使用，但传输不加密；真实公网部署应使用 `wss://`。
- 文本消息和附件 metadata/chunk 已走应用层 AES-256-GCM encrypted relay：Server 只转发 opaque envelope，不能解密应用内容。
- Host/Client 使用 GKA v2：Client 加入时提交临时 X25519 public key，Host 生成 room group key，并为每个成员封装分发；文本和附件使用该 group key 做 AES-256-GCM。
- 成员加入或离开时，Host 会轮换新的 room group key 并重新分发给当前成员。GKA v2 的成员公钥由信令消息携带；如果信令被篡改，恶意或被攻破的 Server 可能尝试公钥替换攻击。
- 房间密码能阻止普通误入，但不能替代 TLS、限速、防火墙和强认证。
- 能限制安全组来源 IP 时，不建议长期使用 `0.0.0.0/0`。
- 不建议把 Web UI 端口 `5188` 直接暴露到公网。
- 长期运行时应使用普通用户，不要用 `root`；`start_server.sh` 默认拒绝 root 运行，临时诊断才可设置 `SECURECHAT_ALLOW_ROOT=1`。部署步骤见 `docs/deployment-hardening.md`，环境变量参考见 `docs/environment-variables.md`，敌手挑战设计见 `docs/adversary-challenges.md`。
- `start_server.sh` 默认把 Server 作为 daemon 常驻，且默认不保存 `server.log`。日志可能包含 room id、用户名和连接状态，只在临时排障时显式启用。
- `start_host.sh` 和 `start_client.sh` 默认前台运行；只有显式 `--daemon` 时才后台运行，并通过短生命周期本地管道传递房间密码。
- 接收附件会写入 `logs/`，需要定期清理并避免直接信任未知文件。

信令和 relay 数据通路安全细节见：

```text
docs/signaling-security.md
docs/relay-attachment-security.md
```

## GKA v2 原理与安全边界

当前 GKA v2 是 Host 协调的群组密钥分发，不是完整的多方 Diffie-Hellman。Host 生成房间级对称密钥 `K_G`，Client 生成自己的 X25519 公私钥对并只上报公钥；Host 使用每个 Client 的公钥封装 `K_G`，Server 只负责转发 opaque `group_key` envelope。

需要注意：系统不会转发任何成员私钥。私钥始终留在本地进程中，被安全转发的是 Host 生成的 room group key。

### X25519 是什么

X25519 是基于 Curve25519 的椭圆曲线 Diffie-Hellman 密钥交换函数。它的作用是：双方各自持有私钥，交换公钥后，在不发送私钥的情况下计算出同一个共享秘密 `S`。这个共享秘密通常不会直接当作 AES 密钥使用，而是先经过 HKDF 派生成固定长度、带上下文绑定的密钥。

X25519 只解决“被动窃听者算不出共享秘密”的问题，不解决“这个公钥到底属于谁”的认证问题。因此在当前代码中，如果信令层公钥被替换，X25519 本身不会检测出该攻击。

数学流程如下。设 X25519 基点为 `G`：

```text
Client:
  c_priv = random()
  c_pub  = c_priv * G

Host 为该 Client 生成一次性封装密钥：
  e_priv = random()
  e_pub  = e_priv * G

Host:
  S = X25519(e_priv, c_pub)

Client:
  S = X25519(c_priv, e_pub)

因为 DH 性质：
  X25519(e_priv, c_priv * G) = X25519(c_priv, e_priv * G)
```

双方用同一个共享秘密派生包装密钥：

```text
K_W = HKDF-SHA256(
  input_key_material = S,
  salt = "securechat-gka-v2:" || roomId,
  info = "group-key|" || clientId,
  length = 32
)
```

Host 用 `K_W` 加密 `K_G`：

```text
group_key_envelope = AES-256-GCM-Encrypt(
  key = K_W,
  plaintext = K_G,
  aad = aadForGroupKey(roomId, clientId)
)
```

Client 收到 `group_key_envelope` 后用自己的 `c_priv` 和 envelope 中的 `ephemeralPublicKey` 重新派生 `K_W`，再解密得到 `K_G`。之后文本和附件都使用 `K_G` 做应用层 AES-256-GCM encrypted relay。

代码入口：

- `include/secure_relay.hpp`：`MemberKeyPair`、`generateMemberKeyPair()`、`encryptGroupKeyForMember()`、`decryptGroupKeyForMember()`。
- `src/client_session_core.cpp`：Client 在 `join_room` 中提交 `publicKey`，并在收到 `group_key` 后解封装。
- `src/host_session_core.cpp`：Host 生成/轮换 `mGroupKey`，收到新 Client 后调用 `encryptGroupKeyForMember()` 单独封装。
- `src/signaling_server.cpp`：Server 校验字段、转发 `publicKey` 和 `group_key` envelope，但不生成、不解密、不理解 group key。
- `src/secure_relay.cpp`：X25519 ECDH、HKDF-SHA256、AES-256-GCM 封装和 relay 加解密实现。

关键实现片段：

```cpp
// 生成 X25519 成员密钥对。publicKey 通过信令发送，privateKey 留在本地。
MemberKeyPair generateMemberKeyPair() {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 || EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        throw std::runtime_error("X25519 key generation failed");
    }
    ...
}
```

```cpp
// 用本地私钥和对端公钥计算 X25519 共享秘密 S。
std::vector<unsigned char> deriveX25519Secret(
    const std::vector<unsigned char>& privateKey,
    const std::vector<unsigned char>& peerPublicKey) {
    auto local = rawX25519PrivateKey(privateKey);
    auto peer = rawX25519PublicKey(peerPublicKey);
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(local.get(), nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY_derive_init(ctx.get());
    EVP_PKEY_derive_set_peer(ctx.get(), peer.get());

    std::size_t len = 0;
    EVP_PKEY_derive(ctx.get(), nullptr, &len);
    std::vector<unsigned char> secret(len);
    EVP_PKEY_derive(ctx.get(), secret.data(), &len);
    return secret;
}
```

```cpp
// Host 为单个 Client 封装 room group key。
json encryptGroupKeyForMember(
    const std::vector<unsigned char>& groupKey,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey) {
    const auto recipientPublic = base64Decode(targetPublicKey);
    auto ephemeral = generateMemberKeyPair();
    const auto secret = deriveX25519Secret(ephemeral.privateKey, recipientPublic);
    const auto wrapKey = hkdfSha256(secret, "securechat-gka-v2:" + roomId, "group-key|" + targetId);

    return encryptWithAesGcm(plaintext, wrapKey, aadForGroupKey(roomId, targetId), {
        {"type", GroupKeyType},
        {"ephemeralPublicKey", ephemeral.publicKey}
    });
}
```

```cpp
// Client 用自己的私钥和 Host 的 ephemeralPublicKey 解封装 group key。
std::vector<unsigned char> decryptGroupKeyForMember(
    const json& envelope,
    const std::string& roomId,
    const std::string& clientId,
    const std::vector<unsigned char>& privateKey) {
    const auto ephemeralPublic = base64Decode(envelope.value("ephemeralPublicKey", ""));
    const auto secret = deriveX25519Secret(privateKey, ephemeralPublic);
    const auto wrapKey = hkdfSha256(secret, "securechat-gka-v2:" + roomId, "group-key|" + clientId);
    const auto plaintext = decryptWithAesGcm(envelope, wrapKey, aadForGroupKey(roomId, clientId));
    return {plaintext.begin(), plaintext.end()};
}
```

安全边界：

- 如果没有中间人攻击且 Host 可信，则不可信 Server 和网络旁路看不到聊天/附件明文。
- 其他合法群成员会持有同一个 `K_G`，因此群聊内容对群成员本身不保密。恶意成员可以保存、截图或转发自己收到的明文。
- 当前私发是定向投递：Server 只把密文转发给目标成员，但密文仍使用 room group key，而不是独立点对点私聊密钥。因此它不是密码学意义上的成员专属私聊。
- 当前 GKA v2 的成员公钥由信令消息携带；恶意 Server 或网络中间人如果能篡改信令，可能实施公钥替换攻击。

典型中间人攻击是公钥替换：

```text
1. Client 生成 c_priv/c_pub，并通过 join_room 上报 c_pub。
2. 恶意 Server/MITM 把 c_pub 替换为自己的 m_pub 后发给 Host。
3. Host 误以为 m_pub 属于 Client，于是用 m_pub 封装 room group key。
4. MITM 用 m_priv 解开 group key。
5. MITM 再用真正的 c_pub 重新封装 group key 发给 Client。
6. Client 正常进入房间，但 MITM 也已经获得 group key。
```

## Windows 构建

只构建 C++：

```bat
build.bat
```

构建 WinUI：

```bat
build_win.bat
```

构建 Web UI：

```bat
build_web.bat
```

运行 Windows Web UI：

```bat
dotnet app\web\bin\Release\net10.0\win-x64\SecureChat.Web.dll --urls http://127.0.0.1:5188
```

浏览器打开：

```text
http://127.0.0.1:5188
```

## Linux 环境配置

安装基础工具：

```bash
sudo apt update
sudo apt install -y build-essential ninja-build git curl wget zip unzip tar pkg-config ca-certificates
```

如果系统 CMake 太旧，可以安装新版：

```bash
sudo snap install cmake --classic
hash -r
cmake --version
```

如果需要 Web UI，安装 .NET：

```bash
wget --no-check-certificate https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 10.0 --install-dir "$HOME/.dotnet"

echo 'export DOTNET_ROOT="$HOME/.dotnet"' >> ~/.bashrc
echo 'export PATH="$HOME/.dotnet:$PATH"' >> ~/.bashrc
source ~/.bashrc

dotnet --info
```

安装 vcpkg：

```bash
cd ~
git clone --depth 1 https://github.com/microsoft/vcpkg.git
cd ~/vcpkg
./bootstrap-vcpkg.sh

echo 'export VCPKG_ROOT="$HOME/vcpkg"' >> ~/.bashrc
source ~/.bashrc
```

安装 C++ 依赖：

```bash
$VCPKG_ROOT/vcpkg install libdatachannel openssl nlohmann-json --triplet x64-linux
```

## Linux 构建

只构建 C++：

```bash
cd /SecureChat
chmod +x build.sh
./build.sh
```

成功后应生成：

```text
out/build/x64-linux-release/host
out/build/x64-linux-release/client
out/build/x64-linux-release/server
out/build/x64-linux-release/libnative.so
```

构建 Web UI：

```bash
cd /SecureChat
chmod +x build_web.sh
./build_web.sh
```

## Host 和 Join

Web UI 端口 `5188` 只是浏览器界面端口，不是聊天室端口。

聊天室信令端口示例为：

```text
25566
```

启动不可信 Server：

```bash
./out/build/x64-linux-release/server 25566
```

群主 Host 作为可见成员连接 Server：

```bash
./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room host
```

其他机器加入：

```text
ws://HOST_IP:25566
```

华为云示例：

```text
ws://124.70.71.65:25566
```

上面的 `ws://` 是 insecure mode，配置简单但信令明文。公网安全连接应改用 WSS，例如：

```text
wss://your-domain.example:25566
```

Linux CLI 加入：

```bash
./out/build/x64-linux-release/client ws://124.70.71.65:25566 secure-room user1
```

## 公网云服务器部署

华为云安全组至少需要放行；来源 IP 能固定时，应按 `docs/deployment-hardening.md` 收敛来源 CIDR：

```text
TCP 25566
```

Ubuntu 防火墙：

```bash
sudo ufw allow 25566/tcp
sudo ufw status
```

检查 Server 是否监听：

```bash
ss -lntp | grep ':25566'
```

Windows 测试公网 TCP：

```powershell
Test-NetConnection 124.70.71.65 -Port 25566
```

聊天文本和附件的应用数据都走 TCP `25566` 上的 WebSocket encrypted relay，不需要 STUN 或 UDP 候选端口。

## 运行 Server、Host 和 Client

`server` 是公网常驻的不可信协调者，不是群成员，不会显示在成员列表中；Host 和 Client 都是需要输入房间密码的可见参与者。

同一个 Server 实例可以承载多个不同 `roomId`，但同一个 Server 实例内 `roomId` 不能重复；不同 Server 或不同端口上的房间名可以重复。一台机器可以启动多个 Server，只要监听端口不同。

Host 创建 roomId 后成为第一个群成员和群管理者。Client 加入时把临时 X25519 public key 发给 Server，Server 只转交给 Host；Host 生成/轮换 room group key，并把 group key 用每个 Client 的 public key 单独封装后交给 Server 转发。Server 不生成群密钥，不解密 group key envelope，也不参与密钥协商语义。

公网 Server 默认用 daemon 脚本后台运行：

```bash
cd /SecureChat
chmod +x start_server.sh stop_server.sh start_host.sh stop_host.sh start_client.sh stop_client.sh
./start_server.sh --mode wss
```

`--mode wss` 默认使用：

```text
certs/fullchain.pem
certs/privkey.pem
```

本地或无证书环境可以显式使用 WS：

```bash
./start_server.sh --mode ws
```

群主 Host 默认前台运行，作为可见成员连接 Server：

```bash
./start_host.sh --server wss://chat.la5te2.online:25566
```

其他成员用 Client 加入：

```bash
./start_client.sh --server wss://chat.la5te2.online:25566
```

`start_host.sh` 和 `start_client.sh` 会由底层 CLI 隐藏提示房间密码；前台模式可继续从终端发送消息和文件命令。

文本消息和附件命令 `/image`、`/file`、`/voice` 都通过 Server relay 转发密文；附件 metadata 和二进制 chunk 会在发送端加密，接收端解密后写入本地附件缓存。聊天数据通路是 WebSocket encrypted relay。

私发可使用 `/to <成员名或成员id> <消息>`，附件也可以写成 `/to <成员名或成员id> /image <path>`、`/to <成员名或成员id> /file <path>` 或 `/to <成员名或成员id> /voice <path>`。WinUI/Web 的发送栏也提供 `To: member` 输入框，留空表示群发，填写成员名或 id 表示私发。当前私发是 group key 下的定向投递：Server 只把密文转发给目标成员，但目标消息仍使用当前 room group key，而不是独立的点对点私聊密钥。

如果 Host 或 Client 确实要后台运行，必须显式加 `--daemon`，并从 stdin 或环境变量提供房间密码：

```bash
printf '%s\n' 'your-password' | ./start_host.sh --server wss://chat.la5te2.online:25566 --daemon
printf '%s\n' 'your-password' | ./start_client.sh --server wss://chat.la5te2.online:25566 --daemon
```

查看和停止：

```bash
cat server.pid
ss -lntp | grep ':25566'
./stop_server.sh
./stop_host.sh
./stop_client.sh
```

默认不保存日志。需要临时排障时显式启用：

```bash
export SECURECHAT_SERVER_LOG_FILE=server.log
./start_server.sh --mode wss
tail -f server.log
```

排障后建议删除日志，不要长期保存房间运行信息。

`ws://` 和 `wss://` 不能在同一个端口同时开启。需要同时保留 insecure mode 和 secure mode 时，分别用不同端口运行，或停止后切换模式重启。

## 附件

支持并校验：

- 图片：PNG、JPEG、BMP
- 语音：WAV
- 普通文件：TXT、MD、LOG、CSV、JSON、XML、YAML、INI、CONF、CFG 等文本类文件

发送大小默认统一限制为 100 MB，可通过环境变量覆盖：

```bash
export SECURECHAT_ATTACHMENT_MAX_BYTES=104857600
```

接收文件保存到当前工作目录下：

```text
logs/images
logs/voice
logs/files
```

附件缓存默认总量上限为 512 MB。可通过环境变量覆盖：

```bash
export SECURECHAT_LOGS_MAX_BYTES=1073741824
```

接收端会清理最旧的受管理附件缓存文件，但只清理 `logs/images`、`logs/voice`、`logs/files`。文件扩展名和文件头校验只能降低误传/伪装风险，不等于杀毒。

附件当前已经实现应用层 E2EE relay：文件名、mime、metadata 和 binary chunk 都在 Host/Client 本地加密，Server 只转发 ciphertext。安全边界是：网络路径和不可信 Server 不应看到附件明文；接收成员本机会解密并缓存附件，因此成员设备、用户手动打开文件、图片/音频解码器和本地文件系统仍是信任边界。附件安全边界不覆盖杀毒扫描、沙箱打开、复杂文档格式隔离或恶意文件内容检测。

因此建议总是从项目根目录启动：

```bash
cd /SecureChat
./out/build/x64-linux-release/host --server ws://127.0.0.1:25566 secure-room host
```

## 常见问题

端口被占用：

```bash
ss -lntp | grep ':25566'
kill PID
```

公网 TCP 不通：

```powershell
Test-NetConnection 124.70.71.65 -Port 25566
```

如果 `TcpTestSucceeded` 是 `False`，检查云安全组和 `ufw`。

进入房间但不能发送：

```text
Waiting for room group key
```

检查 Host 是否仍在线、Server 是否能把 `group_key` envelope 转发给 Client，以及 Client 是否已经完成 joined 流程。若需要日志，先用 `SECURECHAT_SERVER_LOG_FILE=server.log ./start_server.sh --mode wss` 临时启用 Server 日志；Host 端可用 `SECURECHAT_LOG_FILE=host.log ./start_host.sh --server wss://chat.la5te2.online:25566 --daemon` 临时排障：

```bash
sudo ufw status
ss -lntp | grep ':25566'
```

Server 仍然监听但新连接 timeout：

```bash
ss -lntp | grep ':25566'
```

可先重启 Server，并重新启动 Host：

```bash
cd /SecureChat
./stop_server.sh
./start_server.sh --mode wss
./start_host.sh --server wss://chat.la5te2.online:25566
```

## 代理说明

Linux 本机有代理：

```bash
export HTTP_PROXY=http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:7897
export http_proxy=http://127.0.0.1:7897
export https_proxy=http://127.0.0.1:7897
```

代理在 Windows，本机通过 SSH 连接服务器：

```powershell
ssh -R 7897:127.0.0.1:7897 MS
```

然后服务器上：

```bash
export HTTP_PROXY=http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:7897
export http_proxy=http://127.0.0.1:7897
export https_proxy=http://127.0.0.1:7897
```
