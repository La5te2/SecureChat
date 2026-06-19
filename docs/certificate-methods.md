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

这两个文件适合保存 Certbot 或其他 ACME 客户端签发的正式域名证书。证书中的域名必须和客户端填写的 Server URL 主机名一致。

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

## 成员 PKI 启用方式

Host 和 Client 必须配置成员 PKI，否则启动失败：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/member-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/member-key.pem
```

成员私钥加密时再配置：

```bash
export SECURECHAT_IDENTITY_KEY_PASS='key-password'
```

每个成员使用自己的成员证书链和私钥，所有成员共享同一个受信任 CA bundle。成员证书的 Key Usage 如果存在，必须允许 `digitalSignature`。当前实现支持 OpenSSL 可验证的 PEM 证书链，以及 Ed25519、ECDSA P-256、RSA/RSA-PSS 等 OpenSSL 支持的签名密钥。

成员私钥始终留在成员本地。WinUI 设置面板保存的是私钥文件路径，程序在本机读取该路径完成签名；私钥内容不会上传给 Server。

## Windows 生成成员 PKI 示例

在项目根目录打开 PowerShell：

```powershell
New-Item -ItemType Directory -Force certs\pki
Set-Location certs\pki
```

生成 Root CA：

```powershell
openssl genpkey -algorithm ED25519 -out root-ca-key.pem

openssl req -x509 -new -key root-ca-key.pem `
  -out root-ca.pem `
  -days 3650 `
  -subj "/CN=SecureChat Example Root CA" `
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" `
  -addext "keyUsage=critical,keyCertSign,cRLSign" `
  -addext "subjectKeyIdentifier=hash"
```

生成 Intermediate CA，并由 Root CA 签发：

```powershell
openssl genpkey -algorithm ED25519 -out intermediate-ca-key.pem

openssl req -new -key intermediate-ca-key.pem `
  -out intermediate-ca.csr `
  -subj "/CN=SecureChat Example Intermediate CA"

@"
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -Encoding ascii intermediate-ca.ext

openssl x509 -req -in intermediate-ca.csr `
  -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial `
  -out intermediate-ca.pem `
  -days 1825 `
  -extfile intermediate-ca.ext
```

准备成员证书扩展：

```powershell
@"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -Encoding ascii member.ext
```

生成 Alice 成员证书链：

```powershell
openssl genpkey -algorithm ED25519 -out alice-key.pem

openssl req -new -key alice-key.pem `
  -out alice.csr `
  -subj "/CN=alice"

openssl x509 -req -in alice.csr `
  -CA intermediate-ca.pem -CAkey intermediate-ca-key.pem -CAcreateserial `
  -out alice-cert.pem `
  -days 365 `
  -extfile member.ext

Get-Content .\alice-cert.pem, .\intermediate-ca.pem |
  Set-Content -Encoding ascii .\alice-chain.pem
```

生成 Bob 成员证书链：

```powershell
openssl genpkey -algorithm ED25519 -out bob-key.pem

openssl req -new -key bob-key.pem `
  -out bob.csr `
  -subj "/CN=bob"

openssl x509 -req -in bob.csr `
  -CA intermediate-ca.pem -CAkey intermediate-ca-key.pem -CAcreateserial `
  -out bob-cert.pem `
  -days 365 `
  -extfile member.ext

Get-Content .\bob-cert.pem, .\intermediate-ca.pem |
  Set-Content -Encoding ascii .\bob-chain.pem
```

回到项目根目录：

```powershell
Set-Location ..\..
```

Windows CLI 使用 Alice 证书：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
```

Bob 把 `alice-chain.pem` 和 `alice-key.pem` 换成 `bob-chain.pem` 和 `bob-key.pem`。WinUI 中选择同样的文件路径。

## Linux 生成成员 PKI 示例

在项目根目录执行：

```bash
mkdir -p certs/pki
```

生成 Root CA：

```bash
openssl genpkey -algorithm ED25519 -out certs/pki/root-ca-key.pem

openssl req -x509 -new -key certs/pki/root-ca-key.pem \
  -out certs/pki/root-ca.pem \
  -days 3650 \
  -subj "/CN=SecureChat Example Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
```

生成 Intermediate CA：

```bash
openssl genpkey -algorithm ED25519 -out certs/pki/intermediate-ca-key.pem

openssl req -new -key certs/pki/intermediate-ca-key.pem \
  -out certs/pki/intermediate-ca.csr \
  -subj "/CN=SecureChat Example Intermediate CA"

cat > certs/pki/intermediate-ca.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req \
  -in certs/pki/intermediate-ca.csr \
  -CA certs/pki/root-ca.pem \
  -CAkey certs/pki/root-ca-key.pem \
  -CAcreateserial \
  -out certs/pki/intermediate-ca.pem \
  -days 1825 \
  -extfile certs/pki/intermediate-ca.ext
```

准备成员证书扩展：

```bash
cat > certs/pki/member.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
```

生成 Alice 成员证书链：

```bash
openssl genpkey -algorithm ED25519 -out certs/pki/alice-key.pem

openssl req -new -key certs/pki/alice-key.pem \
  -out certs/pki/alice.csr \
  -subj "/CN=alice"

openssl x509 -req \
  -in certs/pki/alice.csr \
  -CA certs/pki/intermediate-ca.pem \
  -CAkey certs/pki/intermediate-ca-key.pem \
  -CAcreateserial \
  -out certs/pki/alice-cert.pem \
  -days 365 \
  -extfile certs/pki/member.ext

cat certs/pki/alice-cert.pem certs/pki/intermediate-ca.pem > certs/pki/alice-chain.pem
```

生成 Bob 成员证书链：

```bash
openssl genpkey -algorithm ED25519 -out certs/pki/bob-key.pem

openssl req -new -key certs/pki/bob-key.pem \
  -out certs/pki/bob.csr \
  -subj "/CN=bob"

openssl x509 -req \
  -in certs/pki/bob.csr \
  -CA certs/pki/intermediate-ca.pem \
  -CAkey certs/pki/intermediate-ca-key.pem \
  -CAcreateserial \
  -out certs/pki/bob-cert.pem \
  -days 365 \
  -extfile certs/pki/member.ext

cat certs/pki/bob-cert.pem certs/pki/intermediate-ca.pem > certs/pki/bob-chain.pem
```

Linux CLI 使用 Alice 证书：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
```

Bob 把 `alice-chain.pem` 和 `alice-key.pem` 换成 `bob-chain.pem` 和 `bob-key.pem`。

查看成员证书 SHA-256 指纹：

```bash
openssl x509 -in certs/pki/alice-cert.pem -noout -fingerprint -sha256
```

## 成员 PKI 在协议中的作用

Client 加入房间时，会生成临时 X25519 key pair，并用成员身份私钥签名自己的入房字段。Host 验证证书链、证书有效期、Key Usage、签名算法和签名内容。验证失败时，Host 拒绝该 Client；验证通过后，该 Client 才能参与 GKA epoch。

成员提交 GKA contribution 时也会签名。Host 分发 group state 或 group key envelope 时，会用 Host 身份私钥签名。Client 接收后先验证 Host 证书链和签名，再解封装 group state 并导出房间群聊密钥。

Server 只检查成员 identity 字段的 JSON 结构和大小，然后转发给 Host/Client。Server 不验证应用层成员证书链，也不决定某个成员身份是否可信。

## 房间内封禁

`/evict` 和 `/ban` 使用当前房间内存封禁。Host 把目标成员已经验证通过的叶子证书指纹记录到当前房间状态中，阻止同一证书在当前房间生命周期内重新加入。该状态不跨 Host 进程或跨房间保存。

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
