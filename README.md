# SecureChat

SecureChat 是一个基于 C++ 和 WinUI 的安全双向通信系统。系统提供命令行 Server、Host、Client，以及 Windows WinUI 图形客户端。通信链路采用 WebSocket 作为信令和密文中继通道，聊天文本、附件元数据和附件分片在应用层使用 AES-256-GCM 端到端加密。公网部署时可以使用 WSS/TLS 或 Nginx TLS 反向代理保护传输通道。

## 项目组成

- `src/` 和 `include/`：C++ 核心代码，包含信令服务器、WebSocket 中继、贡献式群组密钥协商、成员 PKI、`entrance.scp` 证书工具、附件传输、CLI 和 native API。
- `app/winui/`：Windows WinUI 图形客户端。
- `certs/`：本地示例证书和证书生成材料。正式部署时应替换为独立生成的证书。
- `docs/`：开发和部署说明，包括启动手册、环境变量、证书生成和安全边界文档。
- `build.bat`：Windows 上构建 C++ 目标。
- `build_win.bat`：Windows 上构建 C++ 目标和 WinUI 客户端。
- `build.sh`：Linux 上构建 C++ 目标。

项目依赖 libdatachannel 的 WebSocket/WebSocketServer 实现。当前通信数据通路是 Server relay 模式，不使用 WebRTC P2P、STUN 或 TURN。

## 系统角色

SecureChat 分为三个运行角色。

- Server 负责监听端口、注册房间、维护连接状态、转发密文 envelope。Server 不持有成员私钥，也不能解密聊天文本或附件内容。
- Host 是创建房间的成员，也是房间生命周期管理者。Host 可以创建房间、关闭房间、禁言或驱逐当前房间成员，并发起新的群组密钥协商 epoch。
- Client 是加入房间的普通成员。Client 参与成员身份认证、群组密钥协商、群聊消息收发和私发消息收发。

同一个 Server 实例可以承载多个不同 room instance。Server 用 opaque room instance token 注册和路由，因此显示房间名可以重复；同一个 room instance token 不能重复。一台机器可以启动多个 Server，只要监听端口不同。同一个 Host 可以创建多个同名房间，每次创建都会生成新的 room instance token 和新的本地 room-dir；重连时 CLI 必须显式传入 `--room-dir`，WinUI 会弹出房间实例选择面板让用户确认具体实例。

## 安全模型

### 加密通道

SecureChat 有两层保护。

第一层是传输层。`wss://` 使用 TLS 保护 Host/Client 到 Server 或反向代理之间的连接。当前正式对外入口应使用 WSS。Nginx/Caddy 等 TLS 反向代理或受保护隧道工具可以把外部流量转发到 SecureChat Server 的本机回环 WS backend，该 backend 要求绑定 `127.0.0.1`、`localhost` 或 `::1`。

第二层是应用层。文本、附件元数据和附件分片在发送端加密，在接收端解密。Server 只转发 ciphertext、nonce、tag 等 envelope 字段，不能读取聊天明文或附件明文。

因此，公网和跨主机入口应填写 `wss://`。手动运行 `server` 且未配置 TLS 路径时，C++ Server 会自动生成本地/局域网开发证书；使用 `start_server.sh` 时，脚本会在未配置证书时使用 `certs/fullchain.pem` 和 `certs/privkey.pem`。`start_server.sh --mode ws` 用于本机回环 WS backend。Host/Client/WinUI 只做 URL 语法校验，连接结果由 Server 监听模式决定。

### 成员 PKI

Host 和 Client 必须具备成员 PKI。成员证书用于证明长期身份，成员私钥用于签名临时 X25519 公钥、GKA 贡献、group-state envelope 和房间控制消息。Server 不验证成员证书链，成员证书链验证发生在 Host/Client 本地。

当前入口使用 `cert.exe` 生成或导入房间级 `entrance.scp`，再通过 `--room-dir` 启动 Host/Client。程序会从房间目录自动读取 trust store、成员证书链、成员私钥、room instance token 和 relay pool。成员私钥带口令时，通过 CLI 的 `--key-pass` 或 WinUI 设置面板中的 `Member key passphrase / 成员私钥口令` 提供。

Host/Client 会验证证书链、证书有效期、Key Usage `digitalSignature`、签名算法一致性和签名内容。缺少有效 room-dir 或房间级 PKI 文件时，Host/Client 启动失败。

成员私钥只在本机使用。WinUI 读取的是 room-dir 中的本机成员私钥文件，不会把私钥内容写入配置文件，也不会上传给 Server。

成员身份分为三层。`baseUsername` 是用户在 CLI/WinUI 输入的原始用户名，可以和其他成员重复；`system username` 是房间级成员证书公钥指纹派生出的协议用户名，格式为 `baseUsername_` 加公钥指纹前 16 位十六进制字符，同一个 room instance 内不能重复；`nickname/displayName` 只用于界面显示，可以重复。Server 放行的 system username 长度预算为 128 字节。WinUI 成员列表显示 nickname 或 base username，不直接显示 system username。

### 贡献式 GKA

GKA 是 Group Key Agreement 的缩写，即群组密钥协商。当前实现采用 Host 发起的贡献式 GKA。Host 负责发起 epoch 和汇总贡献集合，但房间群聊密钥 `K_G` 由所有当前成员的签名随机贡献共同导出。

每个成员为当前 epoch 生成 32 字节随机贡献 `r_i`，并用自己的成员身份私钥签名：

$$
\sigma_i = \mathrm{Sign}(sk_i,\ roomId \parallel epoch \parallel memberId_i \parallel username_i \parallel X25519Pub_i \parallel r_i \parallel nonce_i)
$$

Host 收集当前成员贡献集合 `C = {c_1, c_2, ..., c_n}`，把完整集合放入 group state，再用每个目标成员的临时 X25519 public key 单独封装。Client 解开 group state 后逐个验证贡献签名，并在本地导出群聊密钥：

$$
\begin{aligned}
K_G = \mathrm{HKDF}_{SHA256}(
&\mathrm{Canonical}(C),\\
&salt = D_G \parallel roomToken \parallel epoch,\\
&info = D_R \parallel \mathrm{sort}(memberId_1,\ldots,memberId_n),\\
&length = 32
)
\end{aligned}
$$

其中 `D_G` 是 GKA epoch 的派生标签，`D_R` 是 room group key 的派生标签。标签的作用是把同一套 HKDF 输入绑定到具体用途，避免不同用途的密钥派生互相混用。

`K_G` 就是 room group key，用于群聊文本、群聊附件以及加密中继 payload 的外层保护。成员加入、离开或被驱逐时，Host 会发起新的 GKA epoch，离开成员不会收到新的贡献集合，因此不能导出后续 `K_G`。

### X25519 与 group state 封装

X25519 是基于 Curve25519 的椭圆曲线 Diffie-Hellman 密钥交换函数。它允许双方在不发送私钥的情况下，通过各自私钥和对方公钥计算同一个共享秘密 `S`。

Host 给某个 Client 分发 group state 时，会生成一次性 X25519 密钥对。Host 用一次性私钥和 Client 的已验证 public key 计算共享秘密 `S`，再用 HKDF-SHA256 派生包装密钥 `K_W`：

$$
\begin{aligned}
K_W = \mathrm{HKDF}_{SHA256}(
&S,\\
&salt = D_W \parallel roomToken,\\
&info = D_S \parallel clientId \parallel epoch,\\
&length = 32
)
\end{aligned}
$$

其中 `D_W` 表示 group state 包装密钥用途，`D_S` 表示这次派生服务于指定 Client 和指定 epoch。

Host 用 `K_W` 加密 group state。Client 收到 envelope 后，用自己的 X25519 私钥和 envelope 中的一次性 public key 派生同一个 `K_W`，解密 group state，再从贡献集合导出 `K_G`。

X25519 只解决共享秘密计算问题，不负责身份认证。SecureChat 使用成员证书和签名把成员身份绑定到临时 X25519 public key。

### 私发消息

私发文本和私发附件采用双层加密。

- 外层仍使用 room group key 保护 encrypted relay payload，并通过 Server 广播给房间成员。
- 内层使用发送者一次性 X25519 private key 和目标成员已验证 public key 派生 pairwise key，只允许目标成员解密私发正文或附件分片。

pairwise key 的派生形式为：

$$
S_{AB} = \mathrm{X25519}(ePriv_A,\ XPub_B)
$$

$$
\begin{aligned}
K_{AB} = \mathrm{HKDF}_{SHA256}(
&S_{AB},\\
&salt = D_P \parallel roomId \parallel A \parallel B,\\
&info = D_M \parallel fp_A \parallel fp_B \parallel ePub_A,\\
&length = 32
)
\end{aligned}
$$

其中 `D_P` 表示 pairwise 私发密钥用途，`D_M` 表示 private message 上下文。`fp_A` 和 `fp_B` 是发送者与接收者证书指纹，用于把私发密钥绑定到双方身份。

非目标成员即使持有当前 `K_G`，也只能解开外层并发现目标不匹配，不能解开内层私发内容。

### Server 可见信息

Server 的安全边界是“不读取应用明文”。Server 仍可见部分元数据，包括连接 id、room token、密文长度、消息时序和连接状态。Server 日志会对成员 id 做短哈希脱敏，但 metadata 本身仍属于可观察信息。需要降低 metadata 暴露时，应减少日志、限制访问来源、使用 WSS/TLS，并控制房间规模和消息发送频率。

### Relay Pool

每个 room instance 都有自己的固定 relay pool。Host 创建 `entrance.scp` 时读取本机候选 pool，先按 URL 去重，再向每个当前可连接访问路径发送 `relay_probe`，用 Server 返回的 `relayInstanceId` 识别同一 backend 的多条访问路径，最后选择最多 4 个不同 backend relay 写入准入容器的保密 payload。候选 URL 集合记为 `C`，按 `relayInstanceId` 去重后的当前可连接 relay 集合记为 `P`，房间实际 relay set 记为 `N`，三者关系为 `N ⊆ P` 且 `|N| <= 4`。如果 `wss://127.0.0.1:25566` 和某个 frp 地址最终指向同一个 Server 进程，二者会返回同一个 `relayInstanceId`，实际 relay set 只保留其中一个。Client 导入 `entrance.scp` 后生成同一份 `relay/relay-pool.sqlite3` 本地副本。Host/Client 启动时从 `--room-dir` 读取房间实际 relay set，界面不需要手动填写 Server URL。运行时每次发送都会根据本机连接状态得到当前可用子集 `M(t)`，其中 `M(t) ⊆ N`；暂时不可用的 relay 会进入 `offline` 和本机沉默期，沉默期内不重复重连或刷屏提示，发送前再尝试恢复。

Host 只在房间实际 relay set 上创建同一个 room instance。Client 首次加入时从 `N` 中选择一个 admission relay 发送 pending join；如果该 relay 连接失败，Client 会按 admission secret 派生的排序尝试下一个未处于沉默期的 relay。Host 在产生 pending join 的 relay 上 approve 或 reject。Client 获批并安装房间级成员证书后，会自动连接剩余 relay。Host 对同一已验证成员在其他 relay 上的重复 pending join 做静默批准，不生成新的 pending 卡片，也不触发新的 GKA epoch。

SecureChat 使用一套固定的确定性 relay selector。selector 会对当前可用子集 `M(t)` 中的每个 relay 计算 HMAC-SHA256 score，并按 score 得到 relay 顺序。pending join 阶段还没有 room group key，因此使用 `entrance.scp` 中的 admission secret；GKA 完成后的文本、附件元数据和附件分片使用当前 room group key、room token、epoch、消息类型、routeNonce、messageId、transferId/chunkIndex 和 attempt 等字段派生调度摘要。单 relay 投递取当前 payload 对应排序的第一项，因此相同 pool 长期可用时，不同消息仍会得到不同 relay 顺序。Host 只向已经确认 `room_created` 的 relay 发送房间控制帧和应用中继，避免把房间控制消息投递到尚未承载该 room instance 的 relay。`close_room` 会向 `N` 中已 ready 的 relay 投递同一个 Host 签名关闭事件。

附件元数据会携带整体 `fileHash`、`chunkSize`、`chunkCount`、`chunkHashes` 和 `merkleRoot`。每个附件分片会携带 `chunkHash` 和 `merkleProof`。接收端先验证外层 AEAD，再验证 manifest 中的 Merkle root、分片摘要位置和分片 Merkle proof，最后按 offset 写入缓存并在收齐后计算最终 `fileHash`。这样不同 relay 上乱序到达的分片不会靠到达顺序拼接，损坏或篡改的分片会被拒绝。

文本、附件元数据和附件分片会写入 `messageId` 和 `payloadHash`。发送方保存短期重传副本，并在 payload 发送成功后发送加密 `relay_notice`。接收端收到 notice 后检查本机 seen cache；如果缺少对应 payload，就通过加密 `missing_message` 请求发送方重传。附件接收端会基于 `receivedChunks` 生成 `missingBitmap`，发送端按 bitmap 批量重发缺失 chunk。发送方重传时提升 `attempt`，重新计算 relay 顺序，并保留原始 payloadHash。相同 `messageId` 和相同 `payloadHash` 的副本被视为重复投递；相同 `messageId` 但不同 `payloadHash` 的 payload 会被拒绝为异常投递。

## 构建

### Windows

CMakePresets 使用 `$env{VCPKG_ROOT}` 定位 vcpkg toolchain。假设 vcpkg 安装在 `C:\src\vcpkg`，先在 PowerShell 中设置当前窗口变量：

```powershell
$env:VCPKG_ROOT="C:\src\vcpkg"
```

需要长期保存到用户环境变量时执行：

```powershell
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\src\vcpkg", "User")
```

安装 C++ 依赖：

```powershell
& "$env:VCPKG_ROOT\vcpkg.exe" install libdatachannel openssl nlohmann-json argon2 --triplet x64-windows
```

`x64-windows` 同时支持 Debug 和 Release 构建。只安装 `x64-windows-release` 会缺少 Debug 依赖，`x64-debug` preset 可能无法正常构建；如果只做 Release 发布，可以单独增加 release-only preset 并把该 preset 的 `VCPKG_TARGET_TRIPLET` 改为 `x64-windows-release`。

构建 C++ 目标：

```bat
build.bat
```

构建 C++ 目标和 WinUI：

```bat
build_win.bat
```

生成的 C++ 程序位于：

```text
out\build\x64-release\server.exe
out\build\x64-release\host.exe
out\build\x64-release\client.exe
out\build\x64-release\cert.exe
```

### Linux

安装基础工具：

```bash
sudo apt update
sudo apt install -y build-essential ninja-build git curl wget zip unzip tar pkg-config ca-certificates
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
$VCPKG_ROOT/vcpkg install libdatachannel openssl nlohmann-json argon2 --triplet x64-linux
```

构建：

```bash
cd ~/SecureChat
chmod +x build.sh
./build.sh
```

生成的 C++ 程序位于：

```text
out/build/x64-linux-release/server
out/build/x64-linux-release/host
out/build/x64-linux-release/client
out/build/x64-linux-release/cert
out/build/x64-linux-release/libnative.so
```

## 成员证书

成员证书采用 Root CA、Intermediate CA、成员证书链的结构。Root CA 用作信任根，Intermediate CA 用于签发成员证书。成员证书必须包含可用于数字签名的公钥，成员私钥必须由成员本人保存。

当前推荐使用房间级 `entrance.scp` 流程。Host 创建 room instance 时生成房间级 Root/Intermediate、Host 证书、Host 私钥和加密准入容器；Client 导入 `entrance.scp` 后在本机生成自己的成员私钥和 CSR；Client 连接后先进入 pending 状态，Host 审批时在线签发成员证书响应，Client 安装响应后才成为 active 成员。首次 pending join 的 CSR bundle、设备声明、pending join proof 和 Host 返回的签发响应都会使用 `entrance.scp` 内 admission secret 派生的准入信令密钥加密，Server 只转发 admission-encrypted envelope。

房间级证书是标准 OpenSSL/X.509 证书。证书保留版本、序列号、签发者、使用者、有效期、公钥、Key Usage、Extended Key Usage、Subject/Authority Key Identifier 和签名算法等字段；SecureChat 额外写入 `O=SecureChat`、`serialNumber=<roomInstanceTokenDigest>`、角色、设备名和 Netscape Comment。当前成员个人信息采用用户填写的用户名和本机设备名，不写入真实身份、IP 地址或操作系统密码。成员私钥支持口令保护，口令为空时写普通 PEM，口令非空时写加密 PEM。

典型文件分发边界如下：

- `root-ca.pem` 可以公开分发，但必须通过可信渠道校验指纹。
- `intermediate-ca.pem` 和成员证书链可以公开分发。
- `member-key.pem` 是成员私钥，只能交给对应成员本人保存。
- `member-chain.pem` 是成员证书链，Host/Client 启动时由 room-dir 自动读取。

证书生成和使用方法见 `docs/certificate-methods.md`。正式环境中，不应由同一个普通 Host 长期代管所有成员私钥。更好的流程是成员本地生成私钥和 CSR，由证书签发方只签发证书，不接触成员私钥。

## 运行

### 本机 WSS

CLI 运行时仍需要 `--room-dir` 指向本机房间材料目录。下面示例中 `<room-dir>` 是 `cert.exe create-entrance` 或 `cert import-entrance` 输出的 `roomDir`，目录名形如 `<原始房间名>_<roomInstanceTokenDigest前8位>`。普通用户更推荐使用 WinUI，WinUI 会隐藏该路径。

Windows：

```powershell
Set-Content -Encoding UTF8 relay-pool.txt "wss://127.0.0.1:25566"
.\out\build\x64-release\cert.exe create-entrance --room secure-room --phrase "use-a-long-random-room-phrase" --host alice --pool relay-pool.txt --out logs
.\out\build\x64-release\cert.exe import-entrance --entrance logs\<room-dir>\certs\entrance.scp --phrase "use-a-long-random-room-phrase" --user bob --out logs
```

Linux：

```bash
printf '%s\n' 'wss://127.0.0.1:25566' > relay-pool.txt
./out/build/x64-linux-release/cert create-entrance --room secure-room --phrase "use-a-long-random-room-phrase" --host alice --pool relay-pool.txt --out logs
./out/build/x64-linux-release/cert import-entrance --entrance logs/<room-dir>/certs/entrance.scp --phrase "use-a-long-random-room-phrase" --user bob --out logs
```

然后打开三个终端，先启动 Server，再启动 Host，最后启动 Client。Client 连接后会停留在 pending join。Host 在 CLI 标准输入中执行 `/list` 查看 pending requestId，再执行 `/approve <requestId>`；WinUI Host 可直接左键 pending 成员卡片允许加入。Host 会自动解密准入信令 envelope，校验 Client 的 CSR、room instance 绑定、设备/身份声明和 pending join proof，并在线签发成员证书响应；签发响应同样经 admission-encrypted envelope 返回。Client 安装响应后才会成为 active 成员并收到当前 group key。

Windows：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
.\out\build\x64-release\host.exe --room-dir logs\<room-dir> alice
.\out\build\x64-release\client.exe --room-dir logs\<room-dir> bob
```

Linux：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
./out/build/x64-linux-release/host --room-dir logs/<room-dir> alice
./out/build/x64-linux-release/client --room-dir logs/<room-dir> bob
```

使用 `--room-dir` 时，Host/Client 不需要额外配置成员 PKI 环境变量。

### 直接 WSS

Server 始终启用 TLS。使用正式域名证书手动运行 `server` 时显式设置：

```bash
export SECURECHAT_TLS_CERT_FILE=/path/to/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/path/to/privkey.pem
./out/build/x64-linux-release/server 25566
```

使用 Linux 启动脚本时，如果没有设置上述两个变量，脚本会直接把它们设置为 `certs/fullchain.pem` 和 `certs/privkey.pem`。这两个文件适合保存 Certbot 签发的域名证书，例如 `chat.example.com` 入口证书。本机/局域网运行应直接运行 `server` 可执行文件并保持 TLS 路径环境变量为空，让 C++ Server 自动生成 `certs/server-chain.pem`、`certs/server-key.pem` 和 `certs/local-root-ca.pem`。

Host/Client 连接地址来自 room-dir 内的 `relay/relay-pool.sqlite3`。使用正式域名时，创建 entrance 前把域名入口写入 relay pool 文件：

```bash
printf '%s\n' 'wss://chat.example.com:25566' > relay-pool.txt
./out/build/x64-linux-release/cert create-entrance --room secure-room --phrase "use-a-long-random-room-phrase" --host alice --pool relay-pool.txt --out logs
./out/build/x64-linux-release/host --room-dir logs/<room-dir> alice
./out/build/x64-linux-release/client --room-dir logs/<room-dir> bob
```

如果服务器证书由系统信任 CA 签发，Host/Client/WinUI 不需要额外配置服务器 CA。本地或局域网自签 CA 场景下，CLI 可通过 `SECURECHAT_LOCAL_TLS_CA` 指定 `certs/local-root-ca.pem`；WinUI 可在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择同一个文件。

### Nginx TLS 反向代理

也可以让 Nginx 监听公网 TLS 入口，SecureChat Server 监听本机回环 WS backend：

```text
Host/Client -- WSS --> Nginx :25566 -- local WS --> SecureChat Server 127.0.0.1:25567
```

后端 Server：

```bash
export SECURECHAT_BIND_ADDRESS=127.0.0.1
export SECURECHAT_PORT=25567
./start_server.sh --mode ws
```

Nginx 配置示例：

```nginx
server {
    listen 25566 ssl;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:25567;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

检查并重新加载 Nginx：

```bash
sudo nginx -t
sudo nginx -s reload
```

使用 Certbot 申请 Let's Encrypt 证书的常见命令：

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot certonly --nginx -d chat.example.com
```

`certonly --standalone` 和 `certonly --nginx` 生成的证书文件都可以给 Nginx 使用，差异只在域名验证方式。

## WinUI 使用

WinUI 面向日常使用场景。

1. 打开 WinUI。
2. 如果连接本地/局域网自动生成的 WSS 证书，在设置面板选择 `Local Server TLS CA / 本地服务器 TLS 信任根`。
3. Host 本机 `config.yml` 的 `[pool]` 段保存 relay 入口，每行一个 `wss://host:port`。Host 可在本地编辑该文件，WinUI 设置面板不显示该段。
4. Host 区域输入 Room 和 User，点击 `Create Room / 创建房间`。WinUI 会自动生成 `logs/<原始房间名>_<digest前8位>/certs/entrance.scp`、房间级 Host 证书材料和 `relay/relay-pool.sqlite3`。
5. Host 或 Join 区域点击 `Join Room / 加入房间` 时，WinUI 会弹出房间实例选择面板；确认后才会连接。即使只有一个同名候选房间，也会要求确认。
6. Client 首次加入时在 Join 区域点击 `Import Room / 导入房间`，选择 Host 分发的 `entrance.scp` 文件。导入后本机会在 `logs/<原始房间名>_<digest前8位>/certs/entrance.scp` 保存准入副本。
7. Client 正确解析 `entrance.scp` 后进入 pending 状态。此时发送框禁用，成员列表只显示自己的灰色卡片。
8. Host 界面会显示该 pending 成员的灰色卡片。左键允许加入，右键拒绝加入并封禁该申请指纹。
9. 审批通过后，Host 签发成员证书响应，Client 安装证书并参与 GKA。发送栏留空 `To: Member / 私信对象` 表示群发；填写成员证书指纹前缀表示私发，前缀至少 8 位十六进制字符。
10. 成员列表只显示成员名。点击已加入成员卡片复制证书指纹前 8 位，右键成员卡片切换附件自动预览允许状态。完整证书指纹保留在程序内部，Host 可以通过 `/list` 显式查看。
11. 点击右侧 `Exit / 离开房间` 只离开当前房间并关闭本地连接。Host 需要关闭整个 room instance 时，在消息输入框或 CLI 中手动输入 `/stop_session`。

成员名只用于图形界面展示，不用于私发目标匹配。私发目标使用证书指纹前缀，协议内部仍有连接路由 id，用于 Server relay、身份绑定和排障。

## CLI 命令

Host 管理命令在 Host 输入框或 CLI 标准输入中发送：

```text
/silence <fingerprint-prefix>
/unsilence <fingerprint-prefix>
/evict <fingerprint-prefix>
/list
/approve <requestId>
/reject <requestId> [原因]
/stop_session
```

`silence` 是当前房间内的发送限制。目标成员仍在线并继续参与后续 GKA epoch。

`evict` 会驱逐目标成员，并把该成员已验证证书指纹加入当前房间内存封禁集。封禁不写入磁盘，房间结束后失效。

`list` 会显示 Host、active Client 和 pending join 的 display name、system username、证书指纹和 pending requestId。`approve` 会把已验证的 pending join 提升为 active 成员。`reject` 会拒绝 pending 成员，拒绝响应带 Host 签名。`stop_session` 显式关闭当前 room instance。WinUI 不显示 requestId，点击 pending 成员卡片时会在内部使用 requestId。

私发命令：

```text
/to <fingerprint-prefix> <消息>
/to <fingerprint-prefix> /image <path>
/to <fingerprint-prefix> /file <path>
```

`fingerprint-prefix` 至少 8 位十六进制字符，大小写不敏感。WinUI 左键成员卡片会复制该成员证书指纹前 8 位，可直接粘贴到 `To: Member / 私信对象` 输入框。

附件命令：

```text
/image <path>
/file <path>
```

## 房间生命周期

当前已拆分 Host 断线和显式关闭。Host 关闭 WinUI、结束 Host 进程、按 Ctrl+C、点击 WinUI 的 `Exit / 离开房间`、输入 `/exit` 或发生网络瞬断时，只表示 Host disconnected，Server 保留房间 open 状态和 pending join 队列，Client 只看到 Host 暂离状态。Host 手动输入 `/stop_session` 时才发送带 Host 签名的 `close_room`，Server 广播 `room_closed` 并关闭该 room instance。

Server 使用 SQLite 只保存 room instance 的 open/closed 状态和 pending join 原始请求，默认路径为 `server/state/<timestamp>.sqlite3`，每次启动生成一个新的状态库，避免重启覆盖旧状态；也可通过 `SECURECHAT_SERVER_STATE_DB` 显式指定固定路径。Server SQLite 的字段边界限定为房间可用性状态和待审批入房请求。

Server 进程停止或重启只表示中继暂时不可用，不会把 open 房间标记为 closed。房间进入 closed 状态只能来自 Host 在线发送的签名 `close_room`。

Client 关闭进程或网络断开只表示当前连接离线，不自动吊销成员资格，也不把成员证书指纹写入封禁集。已批准成员重新连接时会再次经过 Host 验证并进入新的 GKA epoch。Host 显式 `/evict` 才移除成员资格、封禁当前房间内证书指纹并触发后续 group key rotation。禁言不改变成员资格，因此不触发重密钥。

## 附件处理

支持的附件类型：

- 图片：PNG、JPG/JPEG、BMP；扩展名和文件头必须匹配。
- 文件：任意格式，按普通附件接收，不自动预览或执行。
- 语音：WinUI 按住录音生成的 WAV；CLI 不提供 `/voice <path>`。

发送大小默认统一限制为 100 MB：

```bash
export SECURECHAT_ATTACHMENT_MAX_BYTES=104857600
```

接收文件保存到当前工作目录，并按 room instance 分层。目录名统一使用 `<原始房间名>_<roomInstanceTokenDigest前8位>`：

```text
logs/<room>_<digest8>/images
logs/<room>_<digest8>/voice
logs/<room>_<digest8>/files
logs/<room>_<digest8>/texts
logs/<room>_<digest8>/certs
logs/<room>_<digest8>/relay
```

接收端保存附件后会做基础隔离标记。Windows 写入 Mark-of-the-Web（MotW）Zone.Identifier；Linux/Unix 移除 owner/group/others 执行位。该保护是 best-effort，文件系统不支持对应能力时不会阻断聊天，但 SecureChat 自身不会自动打开任意 `file` 附件。

音频文件仍可以通过 `/file <path>` 发送，但接收端会按普通文件处理，不进入语音自动播放路径。

附件缓存默认总量上限为 512 MB：

```bash
export SECURECHAT_LOGS_MAX_BYTES=536870912
```

WinUI 对附件预览采用当前房间内的本机 UI 策略。成员默认 Allowed，成员卡片为绿色；右键成员卡片切换为 Blocked 后，图片和音频只显示“附件已接收”，不会自动进入本地解码器。CLI 可使用 `/trust <fingerprint-prefix>` 和 `/untrust <fingerprint-prefix>` 切换同一套本机策略，指纹前缀至少 8 位十六进制字符。Blocked 只保存在当前房间内存中，退出、断开或切换房间后清空。

附件已经实现应用层端到端加密。接收成员本机会解密并缓存附件，因此成员设备、用户手动打开文件、图片/音频解码器和本地文件系统仍是信任边界。文件扩展名、文件头校验、MotW 和去执行位只能降低误传、伪装和误打开风险，不等于杀毒或完整隔离。

## 本地文本历史

WinUI 和 CLI 使用同一套 C++ 本地消息历史模块。当前只保存已经在本端成功解密并显示的 `text` message。

本地文本历史路径为：

```text
logs/texts/<room>_<roomInstanceTokenDigest前8位>/<systemUsername>.sqlite3
```

本地文本历史 SQLite 的字段边界限定为发送者、actor id、显示类型、正文、原始 message JSON 和 `isOwn`。WinUI 重进房间后会读取该库刷新聊天区域，并直接使用 `isOwn` 决定消息在右侧还是左侧，因此不会因为 nickname 重复或 Host 固定 actor id 导致左右方向错误。

## 环境变量

常用环境变量如下。

| 变量 | 作用 |
| --- | --- |
| `SECURECHAT_TLS_CERT_FILE` | Server TLS 证书链；手动运行 Server 时可留空以生成本地证书 |
| `SECURECHAT_TLS_KEY_FILE` | Server TLS 私钥；手动运行 Server 时可留空以生成本地私钥 |
| `SECURECHAT_TLS_KEY_PASS` | Server TLS 私钥密码 |
| `SECURECHAT_SIGNALING_TLS` | Server 是否启用 TLS；默认启用，设为 `0` 时要求 loopback 绑定，用于本机回环 WS backend |
| `SECURECHAT_LOCAL_TLS_CA` | Host/Client/WinUI 连接本地或局域网自签 WSS 时使用的服务器 CA |
| `SECURECHAT_TLS_AUTO_DIR` | 手动运行 Server 时自动生成本地/局域网 TLS 材料的目录 |
| `SECURECHAT_RELAY_PROBE_TIMEOUT_MS` | Host 创建 entrance 时探测候选 relay 的单个 WSS 连接超时，默认 600ms |
| `SECURECHAT_BIND_ADDRESS` | Server 监听地址 |
| `SECURECHAT_PORT` | Server 默认端口 |
| `SECURECHAT_ATTACHMENT_MAX_BYTES` | 附件发送大小上限 |
| `SECURECHAT_LOGS_MAX_BYTES` | 本地附件缓存上限 |
| `SECURECHAT_SERVER_LOG_ENABLED` | Server daemon 日志输出开关；默认写入 `server/logs/server.log` |
| `SECURECHAT_ALLOW_ROOT` | Linux 上允许 root 临时运行 Server |

完整环境变量见 `docs/environment-variables.md`。

## 常见问题

### 端口被占用

Linux：

```bash
ss -lntp | grep ':25566'
kill <pid>
```

Windows：

```powershell
netstat -ano | findstr :25566
taskkill /PID <pid> /F
```

### Client 一直等待 group key

先检查 Client 是否仍处于 pending join。新成员需要 Host 在 WinUI 左键 pending 成员卡片，或在 CLI 执行 `/list` 查看 requestId 后执行 `/approve <requestId>`，才会成为 active 成员并收到当前 group key。然后检查 Host 是否仍在房间内，Server 是否仍在转发 `group_key` envelope，以及 Host/Client 是否使用同一套房间级 PKI 信任根。`start_server.sh` 默认把 Server 日志写入固定位置：

```bash
tail -f server/logs/server.log
```

如需关闭 daemon 日志输出，可在启动前设置 `SECURECHAT_SERVER_LOG_ENABLED=0`。日志可能包含 room token、连接状态和脱敏后的成员标识。

### WSS 与本机 WS backend

正式对外入口应使用 `wss://`。Nginx/Caddy、frp、SSH tunnel 等外层组件可以把外部受保护连接转发到 SecureChat Server 的本机 `127.0.0.1` WS backend。Host/Client/WinUI 只做 URL 语法校验，部署安全策略集中在 Server 监听边界和外层保护组件。

### 构建依赖下载需要代理

Linux 或 Git Bash 中，如果 vcpkg、Git、CMake 下载依赖失败，可以临时设置本机代理。端口按本机代理实际监听端口选择，常见为 `10090` 或 `7897`：

```bash
export http_proxy=http://127.0.0.1:10090   # 或 http://127.0.0.1:7897
export https_proxy=http://127.0.0.1:10090  # 或 http://127.0.0.1:7897
export HTTP_PROXY=http://127.0.0.1:10090   # 或 http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:10090  # 或 http://127.0.0.1:7897
```

下载完成后可以清理代理变量：

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
```

### 公网连接失败

确认域名解析、云防火墙、系统防火墙和 Server 监听端口。使用 Nginx 反向代理时，公网入口端口应由 Nginx 监听，SecureChat backend 建议只监听 `127.0.0.1`。

