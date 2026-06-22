# SecureChat 证书和 PKI

本文档合并说明 SecureChat 当前使用的两类证书。WSS 服务器证书用于保护 Host/Client 到 Server 的传输通道；成员 PKI 证书用于应用层身份签名，绑定成员身份、临时 X25519 公钥、GKA contribution 和 group key 封装。

## 证书类型

| 类型 | 典型文件 | 作用 | 是否分发 |
| --- | --- | --- | --- |
| WSS 服务器证书 | `fullchain.pem`、`privkey.pem` | 证明 Server 或反向代理入口身份，建立 TLS 通道。 | 证书链公开，私钥不分发。 |
| 本地 TLS 信任根 | `local-root-ca.pem`、`local-root-ca-key.pem` | 本机/局域网自动生成 WSS 证书时使用。 | `local-root-ca.pem` 可分发给客户端信任；`local-root-ca-key.pem` 不分发。 |
| 成员 PKI 信任根 | `root-ca.pem` | Host/Client 验证成员身份证书链。 | 可公开分发，但需要通过可信渠道校验指纹。 |
| Intermediate CA | `intermediate-ca.pem`、`intermediate-ca-key.pem` | 签发成员证书。 | 证书可公开，私钥由签发方保存。 |
| 成员证书链 | `alice-chain.pem`、`bob-chain.pem` | 证明成员身份，包含成员证书和 Intermediate CA。 | 可发送给协议对端验证。 |
| 成员私钥 | `alice-key.pem`、`bob-key.pem` | 对 join、GKA contribution、group key envelope 签名。 | 只保存在对应成员本机。 |

## WSS 服务器证书

Linux `start_server.sh` 默认读取：

```text
certs/fullchain.pem
certs/privkey.pem
```

这两个文件适合保存 Certbot 或其他 ACME 客户端签发的正式域名证书。证书中的域名必须和 relay URL 主机名一致。

手动运行 `server` 或 `server.exe` 且 TLS 路径环境变量为空时，C++ Server 会生成本机/局域网开发证书：

```text
certs/local-root-ca.pem
certs/local-root-ca-key.pem
certs/server-chain.pem
certs/server-key.pem
certs/server-cert.pem
```

CLI Host/Client 连接该证书时设置：

```bash
SECURECHAT_LOCAL_TLS_CA=certs/local-root-ca.pem
```

WinUI 连接该证书时，在设置面板的 `Local Server TLS CA / 本地服务器 TLS 信任根` 中选择 `local-root-ca.pem`。

## 使用 Certbot 申请域名证书

前提：

- 域名已经解析到服务器公网地址；
- 服务器安全组和防火墙允许验证所需端口；
- 证书中的域名和客户端连接 URL 一致。

安装 Certbot：

```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

如果服务器上已经使用 Nginx：

```bash
sudo certbot certonly --nginx -d chat.example.com
```

如果没有 Nginx，且 80 端口可临时由 Certbot 占用：

```bash
sudo certbot certonly --standalone -d chat.example.com
```

两种命令生成的证书都可以给 SecureChat 或 Nginx 使用，差异只在域名验证方式。证书通常位于：

```text
/etc/letsencrypt/live/chat.example.com/fullchain.pem
/etc/letsencrypt/live/chat.example.com/privkey.pem
```

复制到项目默认路径：

```bash
cd ~/SecureChat
mkdir -p certs
sudo cp /etc/letsencrypt/live/chat.example.com/fullchain.pem certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.example.com/privkey.pem certs/privkey.pem
sudo chmod 600 certs/privkey.pem
```

也可以在手动启动 Server 时显式指定路径：

```bash
export SECURECHAT_TLS_CERT_FILE=/etc/letsencrypt/live/chat.example.com/fullchain.pem
export SECURECHAT_TLS_KEY_FILE=/etc/letsencrypt/live/chat.example.com/privkey.pem
./out/build/x64-linux-release/server 25566
```

Windows PowerShell 示例：

```powershell
$env:SECURECHAT_TLS_CERT_FILE="D:\SecureChat\certs\fullchain.pem"
$env:SECURECHAT_TLS_KEY_FILE="D:\SecureChat\certs\privkey.pem"
.\out\build\x64-release\server.exe 25566
```

## 本机和局域网开发证书

保持 TLS 路径环境变量为空即可自动生成：

Windows PowerShell：

```powershell
Remove-Item Env:SECURECHAT_TLS_CERT_FILE -ErrorAction SilentlyContinue
Remove-Item Env:SECURECHAT_TLS_KEY_FILE -ErrorAction SilentlyContinue
.\out\build\x64-release\server.exe 25566
```

Linux Bash：

```bash
unset SECURECHAT_TLS_CERT_FILE SECURECHAT_TLS_KEY_FILE
./out/build/x64-linux-release/server 25566
```

自动生成证书只覆盖本机名、`localhost`、回环地址和探测到的本机网卡 IP。它不生成公网域名证书；公网域名证书应使用 Certbot 等外部工具获取。

## 房间级 entrance.scp 工具

房间级 PKI 工具链由 `cert.exe` 提供。它负责创建、检查、导入 `entrance.scp`，生成成员 CSR，并由 Host 的房间级 Intermediate CA 签发成员证书。该工具不会启动聊天会话，也不会把 Root/Intermediate 私钥、成员私钥或 entrance secret 上传给 Server。

创建房间准入容器：

```powershell
.\out\build\x64-release\cert.exe create-entrance `
  --room my-room `
  --phrase "long random room phrase" `
  --host alice `
  --pool relay-pool.txt `
  --out logs
```

该命令会在 `logs/<原始房间名>_<roomInstanceTokenDigest前8位>/` 下生成 room instance 根目录。原始房间名必须能直接作为本机文件夹名使用，包含 `\ / : * ? " < > |`、控制字符、结尾空格或结尾点号时会被拒绝。

```text
certs/entrance.scp
certs/root-ca.pem
certs/root-ca-key.pem
certs/intermediate-ca.pem
certs/intermediate-ca-key.pem
certs/host-key.pem
certs/host-cert.pem
certs/host-chain.pem
certs/room-state.scb
relay/relay-pool.sqlite3
```

`entrance.scp` 是 AES-256-GCM 加密的二进制准入容器，解锁密钥由 Argon2id 从房间短语和容器 salt 派生。外层使用固定 magic、version、KDF 标识、AEAD 标识、KDF 参数、长度字段、salt、nonce、ciphertext 和 tag；Root/Intermediate 公钥证书、准入 secret 和 room instance 信息只在解密后的 JSON payload 中。二进制外层减少了短期分发渠道把 `.scp` 当作文本文件改写的可能性。

`room-state.scb` 是本机私有运行材料，使用 room root 下 `.securechat-local-state-key` 中的 256-bit 本机随机 key 经 AES-256-GCM 加密。它保存 Host/Client 重连所需的 room instance token、admission secret、签名 descriptor、CSR bundle 等内部对象。在线主流程不再生成 `room-runtime.json`、`room-descriptor.json`、`*.csr.json` 或 `*-sign-response.json` 明文中间文件。

房间级证书仍是标准 OpenSSL/X.509 证书。证书文本中包含版本号、序列号、签发者、使用者、有效期、公钥、Key Usage、Extended Key Usage、Subject Key Identifier、Authority Key Identifier 和签名算法等标准字段。SecureChat 额外把房间绑定信息写入证书本体：`O=SecureChat`，`serialNumber=<roomInstanceTokenDigest>`，`OU=Role:<role>`，`OU=Device:<deviceName>`，并在 Netscape Comment 扩展中写入完整 `roomInstanceTokenDigest`、`roomInstanceId` 和角色。当前采用的成员个人信息是用户在界面或 CLI 中填写的 `baseUsername`，以及程序读取到的本机设备名 `deviceName`；系统不会写入真实姓名、身份证明、操作系统登录密码、IP 地址或生物身份信息。

成员名分为三类。`baseUsername` 是用户输入的原始用户名，可以重复；`system username` 是协议和证书签名使用的唯一用户名，格式为 `baseUsername_` 加成员公钥指纹前 16 位十六进制字符；`nickname/displayName` 只用于界面显示，可以重复。Server 的 system username 预算为 128 字节。同一个 room instance 内 system username 不能重复，重复连接会被拒绝；WinUI 成员列表只显示 nickname 或 baseUsername。

Host 创建房间时先生成 Root、Intermediate 和 Host 的密钥对，再用 canonical room name、`roomInstanceId`、准入 secret、Root 公钥指纹、Intermediate 公钥指纹和 Host 公钥指纹构造带长度前缀的 canonical 字段序列，并对该序列计算 SHA-256，得到 `roomInstanceToken`。随后生成 Root/Intermediate/Host 证书，并把 `roomInstanceTokenDigest` 写入证书 subject 和扩展。这样可以避免“token 依赖证书指纹，证书内容又依赖 token”的循环引用，也避免简单分隔符拼接带来的字段边界歧义。

成员私钥支持口令保护。`--key-pass` 为空时写出普通 PEM 私钥；`--key-pass` 非空时写出 `BEGIN ENCRYPTED PRIVATE KEY`，使用 AES-256-CBC 加密 PEM 私钥。私钥口令只在本机用于打开该成员的房间级私钥，不写入 `entrance.scp`，也不会发送给 Server、Host 或其他成员。

`entrance.scp` 内的 admission secret 还用于派生准入信令加密 key。派生方式为 HKDF-SHA256，salt 绑定 `roomInstanceTokenDigest`，info 绑定用途，例如 `pending_join` 或 `sign_response`；加密算法为 AES-256-GCM。首次入房时，Client 把 CSR bundle、设备声明和 pending join proof 放入 admission-encrypted payload；Host approve 时把成员证书签发响应放入 admission-encrypted payload。Server 只看到 envelope 的版本、用途、nonce、ciphertext、tag 和长度，看不到 CSR PEM、设备声明、CSR hash、成员证书 PEM 或签发响应内容。

检查 entrance：

```powershell
.\out\build\x64-release\cert.exe inspect-entrance `
  --entrance logs\<room-dir>\certs\entrance.scp `
  --phrase "long random room phrase"
```

Client 导入 entrance 并在本机生成成员私钥和 CSR：

```powershell
.\out\build\x64-release\cert.exe import-entrance `
  --entrance logs\<room-dir>\certs\entrance.scp `
  --phrase "long random room phrase" `
  --user bob `
  --out logs
```

Host 手工签发 Client CSR。这个命令主要用于开发调试和离线检查，不推荐普通用户手动执行。正常联机场景中，Client 从 `entrance.scp` 导入 room instance token、Root/Intermediate 公钥证书和 signed room descriptor 后，本机生成成员私钥、CSR、设备/身份声明和 pending join proof；这些内部对象写入加密 `room-state.scb`，联机申请和签发响应通过 admission-encrypted payload 传输；Host 在 `/approve` 或 WinUI 左键审批时自动解密、读取 room instance 绑定信息、校验 CSR 和声明，然后在内存中生成签发响应并立即加密发送。

```powershell
.\out\build\x64-release\cert.exe sign-csr `
  --room-dir logs\<room-dir> `
  --csr <csr-file> `
  --user bob
```

Client 安装 Host 返回的签发响应由联机流程自动完成。Host approve 时在内存中生成签发响应，并通过 admission-encrypted payload 返回；Client 验证 CSR hash、成员 public key、证书链和 room instance 绑定后自动安装成员证书链，普通用户不需要落地明文签发响应文件。

查看某个房间目录可用于运行会话的材料：

```powershell
.\out\build\x64-release\cert.exe room-runtime `
  --room-dir logs\<room-dir> `
  --user bob `
  --role client
```

Host/Client CLI 已支持 `--room-dir` 直接加载房间级 PKI 和 room instance token：

```powershell
.\out\build\x64-release\host.exe --room-dir logs\<room-dir> alice
.\out\build\x64-release\client.exe --room-dir logs\<room-dir> bob
```

WinUI 不显示 `room-dir` 路径。Host 面板只需要 Room 和 User，点击创建房间后会自动读取本机 `config.yml` 的 `[pool]` 段，对候选 relay 去重并探测当前可连接入口，再按 `relayInstanceId` 合并同一 Server backend 的多条访问路径，生成 `logs/<原始房间名>_<digest前8位>/certs/entrance.scp`、Host 房间级证书材料和房间实际 relay set 的 SQLite 副本。Join 面板只需要 Room 和 User，点击导入房间后选择 Host 分发的 `entrance.scp`，WinUI 会自动导入并生成本机成员私钥、准入副本和加密运行材料。Client 会先进入 pending 状态，Host 左键 pending 成员卡片允许加入，右键拒绝并封禁该申请指纹。审批通过时，Host 签发成员证书响应，Client 安装后再参与 GKA。

## 成员 PKI 在协议中的作用

Client 加入房间时，会生成临时 X25519 key pair，并用成员身份私钥签名自己的入房字段。Host 验证证书链、证书有效期、Key Usage、签名算法和签名内容。验证失败时，Host 拒绝该 Client；验证通过后，该 Client 才能参与 GKA epoch。

成员提交 GKA contribution 时也会签名。Host 分发 group state 或 group key envelope 时，会用 Host 身份私钥签名。Client 接收后先验证 Host 证书链和签名，再解封装 group state 并导出房间群聊密钥。

Server 只检查成员 identity 字段的 JSON 结构和大小，然后转发给 Host/Client。Server 不验证应用层成员证书链，也不决定某个成员身份是否可信。

## 房间内封禁

`/evict` 使用当前房间内存封禁。Host 把目标成员已经验证通过的叶子证书指纹记录到当前房间状态中，阻止同一证书在当前房间生命周期内重新加入。该状态不跨 Host 进程或跨房间保存。

## 续期和注意事项

Let's Encrypt 证书通常有效期为 90 天。续期后重新复制或更新软链接，并重启 Server：

```bash
sudo certbot renew
cd ~/SecureChat
sudo cp /etc/letsencrypt/live/chat.example.com/fullchain.pem certs/fullchain.pem
sudo cp /etc/letsencrypt/live/chat.example.com/privkey.pem certs/privkey.pem
./stop_server.sh
./start_server.sh
```

注意事项：

- 不要提交 `certs/` 中的任何私钥。
- `certs/fullchain.pem` 和 `certs/privkey.pem` 通常是域名证书，不适合直接用于 `wss://127.0.0.1` 或局域网 IP。
- `local-root-ca.pem` 可分发给客户端用于信任本地 Server；`local-root-ca-key.pem` 是本地 CA 私钥，不能分发。
- `root-ca.pem` 可公开分发，但需要通过可信渠道确认 SHA-256 指纹。
- 成员私钥只属于对应成员。正式使用时更推荐成员本地生成私钥和 CSR，由签发方只签发证书，不接触成员私钥。
- WSS 保护传输通道，聊天内容由应用层加密中继保护。
