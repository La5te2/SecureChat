# SecureChat

SecureChat 是一个基于 C++ 和 WinUI 的安全双向通信系统。系统提供命令行 Server、Host、Client，以及 Windows WinUI 图形客户端。通信链路采用 WebSocket 作为信令和密文中继通道，聊天文本、附件元数据和附件分片在应用层使用 AES-256-GCM 端到端加密。公网部署时可以使用 WSS/TLS 或 Nginx TLS 反向代理保护传输通道。

## 项目组成

- `src/` 和 `include/`：C++ 核心代码，包含信令服务器、WebSocket 中继、贡献式群组密钥协商、成员 PKI、附件传输、CLI 和 native API。
- `app/chat/`：Windows WinUI 图形客户端。
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

同一个 Server 实例可以承载多个不同房间。同一个 Server 实例内房间名不能重复；不同 Server 或不同端口上的房间名可以重复。一台机器可以启动多个 Server，只要监听端口不同。

## 安全模型

### 加密通道

SecureChat 有两层保护。

第一层是传输层。`wss://` 使用 TLS 保护 Host/Client 到 Server 或反向代理之间的连接。当前正式入口强制使用 WSS，不再提供 `ws://` 明文信令模式。

第二层是应用层。文本、附件元数据和附件分片在发送端加密，在接收端解密。Server 只转发 ciphertext、nonce、tag 等 envelope 字段，不能读取聊天明文或附件明文。

因此，Host/Client/WinUI 的 Server URL 必须以 `wss://` 开头。手动运行 `server` 且未配置 TLS 路径时，C++ Server 会自动生成本地/局域网开发证书；使用 `start_server.sh` 时，脚本会在未配置证书时使用 `certs/fullchain.pem` 和 `certs/privkey.pem`。

### 成员 PKI

Host 和 Client 必须配置成员 PKI。成员证书用于证明长期身份，成员私钥用于签名临时 X25519 公钥、GKA 贡献和 group-state envelope。Server 不验证成员证书链，成员证书链验证发生在 Host/Client 本地。

必须配置的环境变量：

```bash
SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
SECURECHAT_IDENTITY_CERT_FILE=certs/pki/member-chain.pem
SECURECHAT_IDENTITY_KEY_FILE=certs/pki/member-key.pem
```

如果成员私钥带密码，还需要设置：

```bash
SECURECHAT_IDENTITY_KEY_PASS=your-key-password
```

Host/Client 会验证证书链、证书有效期、Key Usage `digitalSignature`、签名算法一致性和签名内容。缺少完整 PKI 配置时，Host/Client 启动失败。

成员私钥只在本机使用。WinUI 设置面板保存的是私钥文件路径，不会把私钥内容写入配置文件，也不会上传给 Server。

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

## 构建

### Windows

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
$VCPKG_ROOT/vcpkg install libdatachannel openssl nlohmann-json --triplet x64-linux
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
out/build/x64-linux-release/libnative.so
```

## 成员证书

成员证书建议采用 Root CA、Intermediate CA、成员证书链的结构。Root CA 用作信任根，Intermediate CA 用于签发成员证书。成员证书必须包含可用于数字签名的公钥，成员私钥必须由成员本人保存。

典型文件分发边界如下：

- `root-ca.pem` 可以公开分发，但必须通过可信渠道校验指纹。
- `intermediate-ca.pem` 和成员证书链可以公开分发。
- `member-key.pem` 是成员私钥，只能交给对应成员本人保存。
- `member-chain.pem` 是成员证书链，Host/Client 启动时通过 `SECURECHAT_IDENTITY_CERT_FILE` 指定。

证书生成方法见 `docs/certificate_methods.md` 和 `docs/pki-identity.md`。正式环境中，不应由同一个普通 Host 长期代管所有成员私钥。更好的流程是成员本地生成私钥和 CSR，由证书签发方只签发证书，不接触成员私钥。

## 运行

### 本机 WSS

打开三个终端，先启动 Server，再启动 Host，最后启动 Client。

Windows：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
$env:SECURECHAT_LOCAL_TLS_CA="certs\local-root-ca.pem"
.\out\build\x64-release\host.exe --server wss://127.0.0.1:25566 secure-room alice
.\out\build\x64-release\client.exe wss://127.0.0.1:25566 secure-room bob
```

Linux：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
export SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
./out/build/x64-linux-release/host --server wss://127.0.0.1:25566 secure-room alice
./out/build/x64-linux-release/client wss://127.0.0.1:25566 secure-room bob
```

Host/Client 启动前需要配置成员 PKI 环境变量。WinUI 可以直接双击启动，并在设置面板中选择 trust store、成员证书链和成员私钥。

### 直接 WSS

Server 始终启用 TLS。使用正式域名证书手动运行 `server` 时显式设置：

```bash
export SECURECHAT_TLS_CERT_FILE=/path/to/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/path/to/privkey.pem
./out/build/x64-linux-release/server 25566
```

使用 Linux 启动脚本时，如果没有设置上述两个变量，脚本会直接把它们设置为 `certs/fullchain.pem` 和 `certs/privkey.pem`。这两个文件适合保存 Certbot 签发的域名证书，例如云端 `chat.example.com` 入口证书。本机/局域网测试应直接运行 `server` 可执行文件并保持 TLS 路径环境变量为空，让 C++ Server 自动生成 `certs/server-chain.pem`、`certs/server-key.pem` 和 `certs/local-root-ca.pem`。

Host/Client 连接：

```bash
./out/build/x64-linux-release/host --server wss://chat.example.com:25566 secure-room alice
./out/build/x64-linux-release/client wss://chat.example.com:25566 secure-room bob
```

如果服务器证书由系统信任 CA 签发，Host/Client/WinUI 不需要额外配置服务器 CA。本地或局域网自签 CA 场景下，CLI 可通过 `SECURECHAT_LOCAL_TLS_CA` 指定 `certs/local-root-ca.pem`；WinUI 可在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择同一个文件。

### Nginx TLS 反向代理

也可以让 Nginx 监听公网 TLS 入口，SecureChat Server 只监听本机 WSS backend：

```text
Host/Client -- WSS --> Nginx :25566 -- local WSS --> SecureChat Server 127.0.0.1:25567
```

后端 Server：

```bash
export SECURECHAT_BIND_ADDRESS=127.0.0.1
export SECURECHAT_PORT=25567
export SECURECHAT_TLS_CERT_FILE=/path/to/backend-fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/path/to/backend-privkey.pem
./out/build/x64-linux-release/server 25567
```

Nginx 配置示例：

```nginx
server {
    listen 25566 ssl;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:25567;
        proxy_ssl_verify off;

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
2. 在设置面板选择 `Trust store`、`Identity certificate` 和 `Identity private key`。
3. 在 Host 区域输入房间名、用户名和 Server URL，创建房间。
4. 在 Join 区域输入房间名、用户名和 Server URL，加入房间。
5. 发送栏留空 `To: member` 表示群发；填写成员名表示私发。
6. 成员列表只显示成员名。点击成员卡片复制完整证书指纹，右键成员卡片切换附件自动预览允许状态。
7. Host 点击 `Stop Session` 会关闭房间并让其他成员退出。

成员名用于图形界面展示和私发目标匹配。协议内部仍有 member id，用于路由、身份绑定和排障。

## CLI 命令

Host 管理命令在 Host 输入框或 CLI 标准输入中发送：

```text
/silence <成员名或成员id>
/unsilence <成员名或成员id>
/evict <成员名或成员id>
/ban <成员名或成员id>
```

`silence` 是当前房间内的发送限制。目标成员仍在线并继续参与后续 GKA epoch。

`evict` 和 `ban` 会驱逐目标成员，并把该成员已验证证书指纹加入当前房间内存封禁集。封禁不写入磁盘，房间结束后失效。

私发命令：

```text
/to <成员名> <消息>
/to <成员名> /image <path>
/to <成员名> /file <path>
/to <成员名> /voice <path>
```

附件命令：

```text
/image <path>
/file <path>
/voice <path>
```

## 房间生命周期

当前房间不做持久化。Host 关闭 WinUI、结束 Host 进程、按 Ctrl+C 或点击 `Stop Session` 都会关闭房间。Server 会通知 Clients 离开该 room，但 Server 进程继续监听。

Client 主动离开、断线或被 Host 驱逐后，Host 会移除其 public key 并发起新的 GKA epoch。禁言不改变成员资格，因此不触发重密钥。

## 附件处理

支持的附件类型：

- 图片：PNG、JPEG、BMP
- 语音：WAV
- 普通文本类文件：TXT、MD、LOG、CSV、JSON、XML、YAML、INI、CONF、CFG 等

发送大小默认统一限制为 100 MB：

```bash
export SECURECHAT_ATTACHMENT_MAX_BYTES=104857600
```

接收文件保存到当前工作目录：

```text
logs/images
logs/voice
logs/files
```

附件缓存默认总量上限为 512 MB：

```bash
export SECURECHAT_LOGS_MAX_BYTES=536870912
```

WinUI 对附件预览采用当前房间内的本机 UI 策略。成员默认 Allowed，成员卡片为绿色；右键成员卡片切换为 Blocked 后，图片和音频只显示“附件已接收”，不会自动进入本地解码器。Blocked 只保存在当前房间内存中，退出、断开或切换房间后清空。

附件已经实现应用层端到端加密。接收成员本机会解密并缓存附件，因此成员设备、用户手动打开文件、图片/音频解码器和本地文件系统仍是信任边界。文件扩展名和文件头校验只能降低误传或伪装风险，不等于杀毒或沙箱隔离。

## 环境变量

常用环境变量如下。

| 变量 | 作用 |
| --- | --- |
| `SECURECHAT_PKI_TRUST_STORE` | Host/Client 信任根证书文件 |
| `SECURECHAT_IDENTITY_CERT_FILE` | Host/Client 成员证书链 |
| `SECURECHAT_IDENTITY_KEY_FILE` | Host/Client 成员私钥 |
| `SECURECHAT_IDENTITY_KEY_PASS` | 成员私钥密码 |
| `SECURECHAT_TLS_CERT_FILE` | Server TLS 证书链；手动运行 Server 时可留空以生成本地证书 |
| `SECURECHAT_TLS_KEY_FILE` | Server TLS 私钥；手动运行 Server 时可留空以生成本地私钥 |
| `SECURECHAT_TLS_KEY_PASS` | Server TLS 私钥密码 |
| `SECURECHAT_LOCAL_TLS_CA` | Host/Client/WinUI 连接本地或局域网自签 WSS 时使用的服务器 CA |
| `SECURECHAT_TLS_AUTO_DIR` | 手动运行 Server 时自动生成本地/局域网 TLS 材料的目录 |
| `SECURECHAT_BIND_ADDRESS` | Server 监听地址 |
| `SECURECHAT_PORT` | Server 默认端口 |
| `SECURECHAT_ROOM_PASSWORD` | CLI Host/Client 的房间密码 |
| `SECURECHAT_ATTACHMENT_MAX_BYTES` | 附件发送大小上限 |
| `SECURECHAT_LOGS_MAX_BYTES` | 本地附件缓存上限 |
| `SECURECHAT_SERVER_LOG_FILE` | Server 日志文件 |
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

检查 Host 是否仍在房间内，Server 是否仍在转发 `group_key` envelope，以及 Host/Client 是否使用同一套成员 PKI 信任根。需要排障时可以临时启用日志：

```bash
export SECURECHAT_SERVER_LOG_FILE=server.log
./out/build/x64-linux-release/server 25566
```

排障完成后建议删除日志。日志可能包含 room token、连接状态和脱敏后的成员标识。

### 只能使用 wss

正式入口只接受 `wss://`。Server 永远以 TLS WebSocket 启动，Host/Client/WinUI 会拒绝 `ws://` URL。

### 公网连接失败

确认域名解析、云防火墙、系统防火墙和 Server 监听端口。使用 Nginx 反向代理时，公网入口端口应由 Nginx 监听，SecureChat backend 建议只监听 `127.0.0.1`。

