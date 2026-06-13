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
- Host/Client 使用贡献式 GKA v3：每个成员为当前 epoch 生成并签名随机贡献，Host 只负责发起 epoch、汇总贡献集合和关闭房间；最终 room group key 由成员本地从贡献集合导出。
- 成员加入或离开时，Host 会发起新的 GKA epoch；离开成员不再收到后续贡献集合，因此不能导出新的 room group key。
- 私发文本和私发附件使用双层加密：外层仍走 room group key 保护 relay envelope，但 Server 不再按目标定向投递，而是广播外层密文；内层使用发送者临时 X25519 和目标成员已验证 public key 派生 pairwise key。没有目标成员私钥的 Server、Host 或其他 Client 不能解内层私发内容。
- PKI 身份认证是 Host/Client 必需配置：成员身份私钥会签名 `join_room` 绑定、GKA 贡献和 Host 的 `group_key`/group-state envelope；接收端验证证书链、吊销状态和签名后才接受成员公钥、贡献集合和新 group key。
- Host 可使用 `/silence`、`/unsilence`、`/evict` 或 `/ban` 管理当前房间成员。禁言只阻止目标 Client 发送 encrypted relay；驱逐会踢出成员，并在当前房间生命周期内封禁其已验证成员证书指纹。
- 可选 mTLS 部署已提供：Nginx 在公网入口要求 TLS 客户端证书，SecureChat Server 作为本机 WebSocket backend 运行。模板见 `deploy/securechat-nginx-mtls.conf` 和 `deploy/securechat-server-mtls-backend.service`。
- 房间密码能阻止普通误入，但不能替代 TLS、限速、防火墙和强认证。
- 能限制安全组来源 IP 时，不建议长期使用 `0.0.0.0/0`。
- 不建议把 Web UI 端口 `5188` 直接暴露到公网。
- 长期运行时应使用普通用户，不要用 `root`；`start_server.sh` 默认拒绝 root 运行，临时诊断才可设置 `SECURECHAT_ALLOW_ROOT=1`。部署步骤见 `docs/deployment-hardening.md`，环境变量参考见 `docs/environment-variables.md`，成员身份 PKI 见 `docs/pki-identity.md`，敌手挑战设计见 `docs/adversary-challenges.md`。
- `start_server.sh` 默认把 Server 作为 daemon 常驻，且默认不保存 `server.log`。日志可能包含 room id、用户名和连接状态，只在临时排障时显式启用。
- `start_host.sh` 和 `start_client.sh` 默认前台运行；只有显式 `--daemon` 时才后台运行，并通过短生命周期本地管道传递房间密码。
- 接收附件会写入 `logs/`，需要定期清理并避免直接信任未知文件。

信令和 relay 数据通路安全细节见：

```text
docs/signaling-security.md
docs/relay-attachment-security.md
docs/pki-identity.md
docs/security-tests.md
docs/acceptance-guide.md
docs/cpp-csharp-guide.md
```

## 完整测试流程

本节只给出从“已经能构建”到“能证明功能和安全边界”的测试主线。安装、编译、运行命令和部署细节已经在后续小节展开：Windows 构建见 [Windows 构建](#windows-构建)，Linux 环境和构建见 [Linux 环境配置](#linux-环境配置) 与 [Linux 构建](#linux-构建)，成员 PKI 见 [PKI 身份认证](#pki-身份认证)，mTLS 入口见 [mTLS 反向代理部署](#mtls-反向代理部署)，公网部署见 [公网云服务器部署](#公网云服务器部署)，启动命令见 [运行 Server、Host 和 Client](#运行-serverhost-和-client)。

### 1. 本地局域网功能测试

1. 按 [Windows 构建](#windows-构建) 或 [Linux 构建](#linux-构建) 生成 `server`、`host`、`client`、WinUI 和 Web UI。
2. 按 [PKI 身份认证](#pki-身份认证) 准备测试 Root CA、Host 证书、Client 证书。Server 不需要成员 PKI 环境变量；Host/Client/WinUI/Web 作为聊天成员必须配置成员证书、成员私钥和信任根。
3. 启动本地 Server，例如 `ws://127.0.0.1:25566`。具体命令见 [运行 Server、Host 和 Client](#运行-serverhost-和-client)。
4. 用 Host 创建一个 room，再用 Client、第二个 WinUI 或 Web UI 加入同一 room。
5. 确认成员列表显示 `name / id`，身份框为绿色；点击身份框应复制完整证书指纹。
6. 测试群发文本、`To: member` 私发文本、图片、WAV 语音和普通文件附件。
7. 测试附件预览策略：未知成员附件默认只显示“附件已接收”；手动标记为 Trusted 后，再按图片/音频自动预览开关预览。
8. Host 输入 `/silence <成员名或id>` 后让目标发送文本或附件，应只收到“member is silenced”提示；`/unsilence <成员名或id>` 后恢复发送。
9. Host 输入 `/evict <成员名或id>` 或 `/ban <成员名或id>`，目标 Client 被断开；同一成员证书在当前房间内再次加入会被拒绝。
10. 让成员离开或断线，观察成员状态、Host 侧 GKA epoch 更新和后续消息可读性。

预期结果：

- 房间只能由 Host 创建，Client 只能加入已有房间。
- Server 只保存房间注册、成员连接状态和密文 relay 状态，不显示聊天明文、附件名明文或附件 metadata 明文。
- Host/Client 缺少完整 PKI 配置时启动失败。
- 私发消息通过广播外层 relay 送达房间成员；非目标成员解开外层后会因 `relayTargetId` 不匹配丢弃，且缺少内层 pairwise key，不能读取私发正文或附件 chunk。

### 2. 公网 WSS 测试

1. 按 [公网云服务器部署](#公网云服务器部署) 将域名解析到云服务器公网 IP，并放行 SecureChat 入口端口。
2. 准备服务器 TLS 证书，使用 `wss://<domain>:25566` 启动 Server。启动脚本和证书位置见 [运行 Server、Host 和 Client](#运行-serverhost-和-client)。
3. Host 和 Client 分别使用自己的成员证书连接公网 `wss://` 地址。
4. 在 Wireshark 或服务器抓包工具中观察公网链路。

预期结果：

- DNS 只负责把域名解析到公网 IP；没有 WebRTC 点对点链路，也不需要 STUN。
- `wss://` 链路上只能看到 TLS record、IP、端口和连接时序，不能直接看到信令 JSON、聊天文本、附件名或 group key。
- Server 日志即使开启 `SECURECHAT_SERVER_LOG_FILE`，也不应包含聊天文本或原始附件名。

### 3. mTLS 反向代理测试

1. 按 [mTLS 反向代理部署](#mtls-反向代理部署) 让 Nginx 监听公网 `25566`，SecureChat Server 只监听 `127.0.0.1:25567`。
2. Host/Client 同时配置应用层成员 PKI 和 TLS 客户端证书。
3. 分别测试“带正确客户端 TLS 证书”和“不带客户端 TLS 证书”的连接。
4. 在服务器上检查监听状态：

```bash
ss -lntp | grep -E ':25566|:25567'
```

预期结果：

- 公网只暴露 Nginx 的 `25566`。
- 后端 `25567` 只在本机监听，不能从公网直接连接。
- 没有合法 TLS 客户端证书的连接会在反向代理层被拒绝；通过 mTLS 的连接仍需通过应用层 PKI 身份认证。

### 4. PKI 和 GKA 安全测试

1. 不设置 `SECURECHAT_PKI_TRUST_STORE`、`SECURECHAT_IDENTITY_CERT_FILE` 或 `SECURECHAT_IDENTITY_KEY_FILE`，Host/Client 应直接启动失败。
2. 用错误 Root CA、过期证书、非 `digitalSignature` 用途证书或吊销指纹测试加入流程。
3. 篡改 `join_room.publicKey`、`identity.signature` 或 `identity.nonce`，Host 应拒绝该 Client。
4. 篡改 `gka_contribution.ciphertext`、`group_key.ciphertext`、`ephemeralPublicKey`、`tag` 或 Host identity，Host/Client 应拒绝对应贡献或 group state。
5. 在普通 `ws://` 本地测试中抓包，确认中继信令可见但聊天内容、附件 metadata、GKA contribution secret 和 group key 不以明文出现。

预期结果：

- 应用层 PKI 绑定成员长期签名身份和临时 X25519 公钥，防止 Server 或中间人静默替换成员公钥。
- GKA v3 的 room group key 由成员签名贡献集合导出；Server 只能转发加密 contribution 和 group-state envelope，不能计算 `K_G`。

### 5. 敌手挑战和部署面测试

更完整的敌手步骤见 `docs/adversary-challenges.md` 和 `docs/security-tests.md`。README 只保留最常用的验收入口：

```bash
nmap -Pn -p 22,80,443,25566,25567,5188 chat.la5te2.online
ss -lntp
sudo ufw status
```

预期结果：公网只暴露必要端口；Web UI `5188` 不直接暴露；mTLS 后端 `25567` 只监听 `127.0.0.1`。

低速、限量 TCP 半连接测试只在自有服务器上执行：

```bash
sysctl net.ipv4.tcp_syncookies
sudo nping --tcp -S -p 25566 --rate 10 -c 100 chat.la5te2.online
watch -n 1 "ss -ant state syn-recv | wc -l"
```

预期结果：Linux TCP 栈、云安全组、Nginx 和系统 backlog 承担半连接防护；SecureChat 应用层主要处理 WebSocket 建立之后的超时、连接数和坏消息限制。

## GKA v3 原理与安全边界

当前 GKA v3 是 Host 发起的贡献式群组密钥协商。Host 仍负责创建房间、关闭房间和发起 epoch，但不再单独生成 `K_G`。每个成员为当前 epoch 生成一个 32 字节随机贡献 `r_i`，用自己的长期身份签名密钥签名：

```text
sig_i = Sign(sk_i, roomId || epoch || memberId_i || username_i || X25519_pub_i || r_i || nonce_i)
```

Host 收集当前成员的签名贡献集合 `C = {c_1, c_2, ..., c_n}` 后，把完整集合放入 group state，并用每个目标成员的临时 X25519 public key 单独加密。Client 解开 group state 后逐个验证贡献签名，再本地导出群密钥：

```text
K_G = HKDF-SHA256(
  input_key_material = Canonical(C),
  salt = "securechat-gka-v3:" || roomToken || "|" || epoch,
  info = "room-group-key|" || sorted(memberId_1, ..., memberId_n),
  length = 32
)
```

需要注意：系统不会转发任何成员私钥。成员私钥始终留在本地进程中；Server 只能看到 room token、连接 id、密文长度和时序，不能看到 contribution secret，也不能计算 `K_G`。

私发不直接使用 `K_G` 作为唯一保护。发送者为每条私发生成一次性 X25519 密钥对，和目标成员已验证 public key 计算共享秘密：

```text
S_AB = X25519(e_priv_A, X_pub_B)
K_AB = HKDF-SHA256(S_AB,
                   salt = "securechat-pairwise-v1:" || roomId || A || B,
                   info = "private-message|" || fp_A || fp_B || e_pub_A)
C = AES-256-GCM.Enc(K_AB, nonce, plaintext, AAD_pairwise)
```

外层 `encrypted_relay` 仍使用 `K_G`，用于统一走 Server relay；应用层 senderName、senderKind 和 private targetId 都在外层密文 payload 内。私发的内层 `pairwise_private` 才是真正保护私发正文或附件 chunk 的成员专属密钥。

### X25519 是什么

X25519 是基于 Curve25519 的椭圆曲线 Diffie-Hellman 密钥交换函数。它的作用是：双方各自持有私钥，交换公钥后，在不发送私钥的情况下计算出同一个共享秘密 `S`。这个共享秘密通常不会直接当作 AES 密钥使用，而是先经过 HKDF 派生成固定长度、带上下文绑定的密钥。

X25519 只解决“被动窃听者算不出共享秘密”的问题，不解决“这个公钥到底属于谁”的认证问题。因此 SecureChat 强制使用 PKI 身份认证：Client 会对 `roomId || username || publicKey || nonce` 签名，Host 验证成员证书链和签名后才信任该 public key。

数学流程如下。设 X25519 基点为 `G`：

```text
Client:
  c_priv = random()
  c_pub  = c_priv * G

Host 为该 Client 生成一次性 group-state 封装密钥：
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
  salt = "securechat-gka-state-v3:" || roomToken,
  info = "group-state|" || clientId || "|" || epoch,
  length = 32
)
```

Host 用 `K_W` 加密 group state：

```text
group_key_envelope = AES-256-GCM-Encrypt(
  key = K_W,
  plaintext = { epoch, signed_contributions[] },
  aad = aadForGroupKey(roomToken, clientId, epoch)
)
```

Client 收到 `group_key_envelope` 后用自己的 `c_priv` 和 envelope 中的 `ephemeralPublicKey` 重新派生 `K_W`，再解密得到 group state。Client 验证每个成员贡献签名后，用 `deriveGroupKeyFromContributions()` 导出 `K_G`。之后文本和附件都使用 `K_G` 做应用层 AES-256-GCM encrypted relay。

代码入口：

- `include/secure_relay.hpp`：`generateGroupContribution()`、`deriveGroupKeyFromContributions()`、`encryptGkaContributionForHost()`、`encryptGroupStateForMember()`。
- `src/client_session_core.cpp`：Client 收到 `gka_request` 后提交签名贡献，收到 `group_key` 后验证 group state 并导出 `K_G`。
- `src/host_session_core.cpp`：Host 发起 GKA epoch，汇总签名贡献集合，并把 group state 单独封装给每个 Client。
- `src/signaling_server.cpp`：Server 校验字段、转发 `gka_request`、`gka_contribution` 和 `group_key` envelope，但不生成、不解密、不理解 group key。
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
// 每个成员为 epoch 生成一个签名贡献并加密发给 Host。
void ClientSessionCore::sendGkaContribution(std::uint64_t epoch) {
    const auto contribution = chat::secure_relay::generateGroupContribution();
    json item = {
        {"memberId", mClientId},
        {"username", mUsername},
        {"publicKey", mMemberKeys.publicKey},
        {"contribution", contribution}
    };
    item["identity"] = mIdentity.signGkaContribution(
        mRoomId, epoch, mClientId, mUsername, mMemberKeys.publicKey, contribution);
    auto envelope = chat::secure_relay::encryptGkaContributionForHost(
        item, mRoomToken, mClientId, hostPublicKey, epoch);
    mWs->send(envelope.dump());
}
```

```cpp
// Host 把完整贡献集合封装给单个 Client；Client 解开后自行导出 K_G。
json encryptGroupStateForMember(
    const json& groupState,
    const std::string& roomId,
    const std::string& targetId,
    const std::string& targetPublicKey,
    std::uint64_t epoch) {
    const auto recipientPublic = base64Decode(targetPublicKey);
    auto ephemeral = generateMemberKeyPair();
    const auto secret = deriveX25519Secret(ephemeral.privateKey, recipientPublic);
    const auto wrapKey = hkdfSha256(
        secret,
        "securechat-gka-state-v3:" + roomId,
        "group-state|" + targetId + "|" + std::to_string(epoch));
    return encryptWithAesGcm(groupState.dump(), wrapKey, aadForGroupKey(roomId, targetId, epoch), {
        {"type", GroupKeyType},
        {"version", 3},
        {"epoch", epoch},
        {"ephemeralPublicKey", ephemeral.publicKey}
    });
}
```

安全边界：

- 如果成员证书和本地私钥未泄露，则不可信 Server 和网络旁路看不到聊天/附件明文，也看不到 GKA contribution secret。
- 恶意 Server 不能在不破坏成员身份签名的情况下静默替换 Client 的临时 X25519 public key、成员 GKA 贡献或 Host 签名的 `group_key`/group-state envelope。
- 其他合法群成员会持有同一个 `K_G`，因此群聊内容对群成员本身不保密。恶意成员可以保存、截图或转发自己收到的明文。
- Host 仍是群成员和房间生命周期管理者，因此可以读取群聊内容、驱逐成员或关闭房间；但当前 `K_G` 不再由 Host 单方随机生成，而是由签名贡献集合导出。
- 恶意成员可以拒绝提交 GKA contribution，这属于可用性攻击；Host 会在 10 秒 GKA 超时后自动驱逐仍未提交贡献的成员，并只用剩余成员重新发起 epoch。
- 私发是广播外层 relay 加内层 pairwise 加密：Host/Client 会在解密外层后检查 `relayTargetId`。内层 pairwise key 由发送者临时 X25519 private key 和目标成员已验证 public key 派生，不从 room group key 派生，因此其他成员即使持有当前 `K_G` 也不能解开私发正文或私发附件 chunk。
- Server 仍可见 metadata，包括 room token、连接 id、ciphertext 长度和时序。这会泄露活跃时间和大致内容大小；WSS/mTLS、默认少日志和部署最小暴露只能降低风险，不能隐藏这些模式。
- 接收端维护 relay nonce/tag replay cache；Client 还检查递增的 group key epoch，拒绝重放或过期 `group_key`。这能阻止常见 Server 重放旧 envelope，但不能阻止 Server 直接断连或丢弃新消息。
典型中间人攻击是公钥替换：

```text
1. Client 生成 c_priv/c_pub，并通过 join_room 上报 c_pub。
2. 恶意 Server/MITM 把 c_pub 替换为自己的 m_pub 后发给 Host。
3. Host 误以为 m_pub 属于 Client，于是把 group state 或贡献请求发给攻击者控制的密钥。
4. MITM 尝试解开 group state 或伪造成员贡献。
5. MITM 再用真正的 c_pub 转发给 Client。
6. Client 正常进入房间，但 MITM 也试图进入密钥协商链路。
```

当前实现强制 PKI 身份认证，因此上面的攻击不能静默完成：`join_room.identity` 和 GKA contribution 签名覆盖原始 `publicKey`，Host 会在验证时发现替换；`group_key.identity` 的签名覆盖 group-state envelope 关键字段，Client 会在解封装前发现篡改。

## PKI 身份认证

PKI 身份认证是 Host/Client 必需配置。不配置完整 PKI 环境变量时，Host/Client 启动失败；Server 仍只做字段结构和大小校验，不验证证书链。Host/Client 会加载本机成员证书链、成员身份私钥和受信任 CA bundle。

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/member-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/member-key.pem
```

私钥加密时再设置：

```bash
export SECURECHAT_IDENTITY_KEY_PASS='key-password'
```

本地吊销列表可选：

```bash
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
```

当前实现会验证证书链、有效期、Key Usage `digitalSignature`、本地 SHA-256 指纹吊销列表、签名算法一致性和签名内容。Server 只检查 `identity` 字段结构和大小，然后转发；证书验证发生在 Host/Client 本地。

运行时：

- Client 在 `join_room` 中签名 `roomId`、`username`、临时 X25519 `publicKey` 和 `nonce`。
- 成员在 GKA epoch 中签名 `roomId`、`epoch`、`memberId`、`username`、临时 X25519 `publicKey` 和 contribution secret。
- Host 验证 Client 身份后才记录 public key、发起 GKA epoch，并把完整贡献集合封装给当前成员。
- Host 在 `group_key`/group-state envelope 中签名 room、version、epoch、target、ephemeralPublicKey、ciphertext、tag 和 nonce。
- Client 验证 Host 身份、解封装 group state、逐个验证贡献签名后才导出 room group key。
- Server 的 `room_members.memberInfos` 会携带 Client 入房时提交的 signed identity；其他 Client 复验后才把成员 id/name 映射到 pairwise public key。
- Host 会把已验证成员的证书 SHA-256 指纹和 signed identity 通过加密 `member_identity` 控制消息发给房间成员；接收端会拒绝同一 member id 上的公钥或指纹冲突。WinUI 成员列表用绿色身份框表示已验证成员，点击 `name / id` 框会复制完整证书指纹。

详细字段见 `docs/pki-identity.md`。

## mTLS 反向代理部署

当前 libdatachannel 的 WebSocketServer 不暴露 TLS 客户端证书校验接口，因此 mTLS 在反向代理层实现：

```text
Host/Client -- mTLS WSS --> Nginx :25566 -- local WS --> SecureChat Server 127.0.0.1:25567
```

SecureChat Server backend 启动：

```bash
SECURECHAT_BIND_ADDRESS=127.0.0.1 SECURECHAT_PORT=25567 ./start_server.sh --mode ws
```

Host/Client 连接 mTLS 入口前配置客户端证书：

```bash
export SECURECHAT_MTLS_CLIENT_CERT_FILE=certs/pki/member-chain.pem
export SECURECHAT_MTLS_CLIENT_KEY_FILE=certs/pki/member-key.pem
```

如果 mTLS 入口服务器证书是私有 CA 或自签名证书，再额外设置 `SECURECHAT_TLS_CA_FILE`；使用 Let's Encrypt 等系统已信任 CA 时通常不需要。

Nginx 模板：

```text
deploy/securechat-nginx-mtls.conf
```

systemd backend 模板：

```text
deploy/securechat-server-mtls-backend.service
```

`deploy/` 文件是 Linux 部署模板，不是双击运行程序。普通 systemd 部署时，把 `deploy/securechat-server.service` 复制到 `/etc/systemd/system/securechat-server.service`，检查 `User`、`WorkingDirectory`、`ExecStart` 和证书路径后执行 `sudo systemctl daemon-reload` 与 `sudo systemctl enable --now securechat-server.service`。Nginx+mTLS 部署时，把 Nginx 模板复制到 `/etc/nginx/conf.d/securechat-mtls.conf`，把 backend service 模板复制到 `/etc/systemd/system/securechat-server-mtls-backend.service`，检查证书路径和后端端口后启动 Nginx 与 backend。完整步骤见 `docs/deployment-hardening.md`。

mTLS 只限制“谁能建立到 Server 的 TLS 连接”，当前不是强制部署模式；本地或局域网测试可以继续使用 `ws://`。应用层消息机密性仍由 GKA v3 和 AES-256-GCM 提供，成员身份、GKA 贡献和临时 X25519 key 的绑定仍由强制 PKI 身份认证提供。

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

Host 创建 roomId 后成为第一个群成员和房间生命周期管理者。Client 加入时把临时 X25519 public key 发给 Server，Server 只转交给 Host；Host 发起 GKA epoch，当前成员提交签名随机贡献，Host 汇总后把 group state 用每个 Client 的 public key 单独封装后交给 Server 转发。Server 不生成群密钥，不解密 group state envelope，也不参与密钥协商语义。

当前房间不做持久化：Host 关闭 WinUI、结束 Host 进程、Ctrl+C 或点击 stop session 都会关闭房间，Server 会通知 Clients 退出该 room，但 Server 进程本身继续监听。Client 主动离开、断线或被 Host 驱逐后，Host 会移除其 public key 并发起新的 GKA epoch；禁言不改变成员资格，因此不触发重密钥。

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

私发可使用 `/to <成员名或成员id> <消息>`，附件也可以写成 `/to <成员名或成员id> /image <path>`、`/to <成员名或成员id> /file <path>` 或 `/to <成员名或成员id> /voice <path>`。WinUI/Web 的发送栏也提供 `To: member` 输入框，留空表示群发，填写成员名或 id 表示私发。私发采用外层 room encrypted relay 广播加内层 pairwise encryption；如果目标成员的 PKI 绑定 public key 尚未通过 `room_members.memberInfos`、GKA group state 或 `member_identity` 验证，发送会失败，不会降级为普通 room group key 私发。

Host 管理命令也从普通输入框发送，但不会进入聊天历史：

```text
/silence <成员名或成员id>
/unsilence <成员名或成员id>
/evict <成员名或成员id>
/ban <成员名或成员id>
```

`silence` 是当前房间内的发送限制，目标仍在线并可继续参与后续 GKA epoch；`evict` 和 `ban` 会驱逐目标，并把该成员已验证证书指纹加入当前房间内存封禁集。封禁不写入磁盘，Host 进程或房间结束后失效。

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

WinUI 对附件预览采用当前房间内的身份状态策略：`Unknown` 表示没有 PKI 验证结果，`Verified` 表示成员证书和签名已通过 PKI 验证，`Trusted` 表示 `Verified` 成员又被本机用户允许自动预览，`Blocked` 表示本机用户阻止该成员附件自动预览。`Trusted` 和 `Blocked` 只保存在当前房间内存中，退出、断开或切换房间后清空。默认远端未知成员发来的图片和音频先显示“附件已接收”，只有用户点击“预览”才会触发本地解码器；Verified 成员默认仍不会自动预览，除非用户标记 Trusted，或关闭“仅信任成员自动预览”。设置面板提供“自动预览图片”“自动加载音频”“仅信任成员自动预览”三个开关。WinUI 预览前还会额外检查图片宽高、总像素数、文件大小，以及 WAV 采样率、声道数、时长和 chunk 结构。`MaxPreviewImageBytes`、`MaxPreviewAudioBytes` 只限制本地预览，协议传输大小仍统一由 `SECURECHAT_ATTACHMENT_MAX_BYTES` 控制。

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
