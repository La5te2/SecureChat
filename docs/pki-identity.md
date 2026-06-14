# SecureChat PKI 成员身份认证

本文档说明当前已经实现的阶段 9：用成员身份签名证书绑定 GKA v3 中的临时 X25519 public key 和成员 contribution，降低恶意 Server 或主动中间人替换公钥、伪造贡献或篡改 group state 的风险。

这里的 PKI 证书不是 WSS 服务器证书。WSS 服务器证书用于证明 `wss://chat.la5te2.online:25566` 连接到正确的 Server；成员身份证书用于证明某个 Host/Client 的 `join_room`、GKA contribution 或 `group_key`/group-state envelope 由持有身份私钥的成员签名。

## 启用方式

PKI 是 Host/Client 必需配置。不配置完整 PKI 变量时，Host/Client 启动失败。每个 Host/Client 都必须提供信任根、成员证书链和成员私钥：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/client-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/client-key.pem
```

私钥加密时再配置：

```bash
export SECURECHAT_IDENTITY_KEY_PASS='key-password'
```

本地吊销列表是可选项：

```bash
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
```

Host 和 Client 都使用同一组变量名。实际部署时，每个成员机器使用自己的 `SECURECHAT_IDENTITY_CERT_FILE` 和 `SECURECHAT_IDENTITY_KEY_FILE`，但共享同一个受信任 CA bundle。

## 证书要求

当前实现接受 OpenSSL 能验证的 PEM 证书链，并支持以下身份签名密钥：

- Ed25519；
- ECDSA P-256 等 OpenSSL 支持的 EC 签名密钥，签名摘要为 SHA-256；
- RSA 或 RSA-PSS，签名摘要为 SHA-256。

成员证书的 Key Usage 如果存在，必须允许 `digitalSignature`。代码不会用 X25519 做身份认证；X25519 只用于 ECDH、GKA contribution/state 封装和 pairwise 私发，身份认证由证书里的签名公钥完成。

## 证书生成：Windows PowerShell

本节生成一套实验用 PKI：Root CA 只签 Intermediate CA，成员证书由 Intermediate CA 签发。SecureChat 运行时信任 `root-ca.pem`，成员证书链文件应包含“成员叶子证书 + Intermediate CA 证书”。

在项目根目录打开 PowerShell：

```powershell
New-Item -ItemType Directory -Force certs\pki
Set-Location certs\pki
```

生成 Root CA。Root CA 是信任根，真实部署时应离线保存 `root-ca-key.pem`：

```powershell
openssl genpkey -algorithm ED25519 -out root-ca-key.pem

openssl req -x509 -new -key root-ca-key.pem `
  -out root-ca.pem `
  -days 3650 `
  -subj "/CN=SecureChat Test Root CA" `
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" `
  -addext "keyUsage=critical,keyCertSign,cRLSign" `
  -addext "subjectKeyIdentifier=hash"
```

生成 Intermediate CA，并由 Root CA 签发：

```powershell
openssl genpkey -algorithm ED25519 -out intermediate-ca-key.pem

openssl req -new -key intermediate-ca-key.pem `
  -out intermediate-ca.csr `
  -subj "/CN=SecureChat Test Intermediate CA"

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

准备成员证书扩展。成员证书只允许做数字签名，不是 CA：

```powershell
@"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -Encoding ascii member.ext
```

生成 Host/Alice 的成员身份私钥和证书，并把叶子证书与 Intermediate CA 合成证书链：

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

生成 Client/Bob 的成员身份私钥和证书：

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

创建空吊销列表并回到项目根目录：

```powershell
New-Item -ItemType File -Force revoked.txt
Set-Location ..\..
```

Windows CLI 使用 Alice 证书时：

```powershell
$env:SECURECHAT_PKI_TRUST_STORE="certs\pki\root-ca.pem"
$env:SECURECHAT_IDENTITY_CERT_FILE="certs\pki\alice-chain.pem"
$env:SECURECHAT_IDENTITY_KEY_FILE="certs\pki\alice-key.pem"
$env:SECURECHAT_PKI_REVOCATION_FILE="certs\pki\revoked.txt"
```

WinUI 中填写同样的四个文件路径即可。Bob 把 `alice-chain.pem` 和 `alice-key.pem` 换成 `bob-chain.pem` 和 `bob-key.pem`。

## 证书生成：Linux Bash

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
  -subj "/CN=SecureChat Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
```

生成 Intermediate CA，并由 Root CA 签发：

```bash
openssl genpkey -algorithm ED25519 -out certs/pki/intermediate-ca-key.pem

openssl req -new -key certs/pki/intermediate-ca-key.pem \
  -out certs/pki/intermediate-ca.csr \
  -subj "/CN=SecureChat Test Intermediate CA"

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

生成 Host/Alice 成员证书：

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

生成 Client/Bob 成员证书：

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

创建空吊销列表：

```bash
: > certs/pki/revoked.txt
```

Linux CLI 使用 Alice 证书时：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
```

Bob 把 `alice-chain.pem` 和 `alice-key.pem` 换成 `bob-chain.pem` 和 `bob-key.pem`。

查看成员证书 SHA-256 指纹：

```bash
openssl x509 -in certs/pki/alice-cert.pem -noout -fingerprint -sha256
```

需要长期吊销该证书时，把输出中的十六进制指纹写入 `SECURECHAT_PKI_REVOCATION_FILE` 指向的文本文件。房间内 `/ban` 或 `/evict` 不会写入这个文件。

## join_room 绑定

Client 加入房间时仍会生成临时 X25519 key pair，并把 public key 放入 `join_room`。同时，Client 必须附带 `identity` 对象：

```json
{
  "version": 1,
  "certChainPem": "-----BEGIN CERTIFICATE-----...",
  "nonce": "base64",
  "signatureAlg": "Ed25519",
  "signature": "base64"
}
```

签名覆盖以下规范化字段：

```text
securechat-pki-v1
join_room
roomId:<len>:<roomId>
username:<len>:<username>
publicKey:<len>:<temporary-x25519-public-key>
nonce:<len>:<identity-nonce>
```

Host 收到 `new_client` 后会：

1. 验证成员证书链能追溯到 `SECURECHAT_PKI_TRUST_STORE`；
2. 检查证书有效期和 Key Usage；
3. 检查证书链中任一证书指纹是否在本地吊销列表中；
4. 验证 `signatureAlg` 与证书公钥类型一致；
5. 验证签名确实覆盖当前 `roomId`、`username` 和临时 X25519 public key。

验证失败时，Host 发送 `reject_client`，Server 会移除该 Client 并关闭其 WebSocket。验证通过后，Host 还会检查该证书指纹是否已经被当前房间的 `/evict` 或 `/ban` 命令封禁；若已封禁，Host 拒绝该 Client，不记录 public key，也不允许其参与 GKA epoch。未被封禁时，Host 才记录该 public key，并在成员变化时发起新的 GKA epoch。

## GKA contribution 和 group_key 绑定

每个成员提交 GKA contribution 时，会用自己的身份私钥签名。签名覆盖：

```text
securechat-pki-v1
gka_contribution
roomId:<len>:<roomId>
epoch:<len>:<gka-epoch>
memberId:<len>:<member-id>
username:<len>:<username>
publicKey:<len>:<temporary-x25519-public-key>
contribution:<len>:<base64-contribution-secret>
nonce:<len>:<identity-nonce>
```

Host 给 Client 分发 group state 时，会生成 `group_key` envelope，再用 Host 身份私钥签名。签名覆盖：

```text
securechat-pki-v1
group_key
version:<len>:<envelope-version>
roomId:<len>:<roomId>
epoch:<len>:<group-key-epoch>
targetId:<len>:<clientId>
senderId:<len>:host
alg:<len>:AES-256-GCM
kdf:<len>:X25519-HKDF-SHA256+GKA-Contrib-v3
ephemeralPublicKey:<len>:<host-ephemeral-x25519-public-key>
nonce:<len>:<aes-gcm-nonce>
ciphertext:<len>:<wrapped-group-state>
tag:<len>:<aes-gcm-tag>
identityNonce:<len>:<identity-nonce>
```

Client 在解封装 group state 之前，会先验证 Host 证书链、吊销状态、签名算法和签名。如果验证失败，Client 不会执行 X25519 解封装，也不会接受该 room group key。解开 group state 后，Client 还会验证每个成员的 GKA contribution 签名，再本地导出 `K_G`。

## 验证结果进入 UI

Host 验证 Client 身份后，会记录该成员证书的 SHA-256 指纹和 subject。Server 的 `room_members.memberInfos` 会携带 Client 入房时提交的 `publicKey` 和 signed `identity`，其他 Client 会自行验证签名后才把该 member id/name 作为 pairwise 私发目标。随后 Host 也会通过加密 `member_identity` 控制消息向房间内成员广播已验证成员：

```json
{
  "type": "member_identity",
  "payload": {
    "memberId": "client-id",
    "displayName": "alice",
    "fingerprint": "sha256-hex",
    "subject": "/CN=alice",
    "publicKey": "base64-x25519-public-key",
    "identity": {
      "version": 1,
      "certChainPem": "-----BEGIN CERTIFICATE-----...",
      "nonce": "base64",
      "signatureAlg": "Ed25519",
      "signature": "base64"
    },
    "state": "verified",
    "verifiedBy": "host"
  }
}
```

该控制消息本身仍走应用层 encrypted relay。接收端只接受 relay metadata 显示发送者是 Host 的 `member_identity`，并会重新验证其中的 signed identity；如果同一个 member id 已经有已验证 public key 或证书指纹，后续冲突会被拒绝，不会静默覆盖。WinUI 成员列表中 Verified/Trusted 成员使用绿色 `name / id` 身份框，Unknown/Blocked 使用红色身份框；点击身份框会复制完整证书指纹。用户可以把 `Verified` 成员临时标记为 `Trusted` 以允许自动预览附件，也可以标记为 `Blocked` 禁止自动预览。

私发使用该已验证 member id/name 到 X25519 public key 的映射。发送端找不到目标成员的已验证 public key 时，私发会失败并提示错误，不会降级为仅 room group key 加密。

## 吊销列表

`SECURECHAT_PKI_REVOCATION_FILE` 是本地受信任文本文件，每行一个 SHA-256 证书指纹，大小写和冒号不敏感：

```text
# revoked.txt
9F:12:AB:...
7c32aa...
```

当前实现会检查 identity 证书链中的每张证书。如果叶子证书或中间证书的 SHA-256 指纹出现在吊销列表中，该 identity 会被拒绝。成员被拒绝或离开后，Host 的既有成员变化逻辑会发起新的 GKA epoch。

`/evict` 和 `/ban` 使用的是另一层当前房间内存封禁：Host 把目标成员已经验证通过的叶子证书指纹记录到当前房间状态中，防止同一证书在该房间生命周期内重新加入。它不写入 `SECURECHAT_PKI_REVOCATION_FILE`，也不会跨 Host 进程或跨房间保留。需要跨房间、跨重启的拒绝时，应把证书指纹写入受信任吊销列表。

## 代码位置

- `include/identity_pki.hpp`：PKI 身份上下文接口。
- `src/identity_pki.cpp`：证书链验证、吊销检查、签名与验签。
- `src/client_session_core.cpp`：Client 在 `join_room` 和 GKA contribution 中签名身份，收到 `group_key` 后验证 Host 身份、验证 contribution set，并复验 `room_members.memberInfos` / `member_identity` 中的成员 public key。
- `src/host_session_core.cpp`：Host 验证 Client 身份，验证 GKA contribution，签名 `group_key`/group-state envelope，广播 verified member identity，并拒绝验证失败的 Client。
- `src/signaling_server.cpp`：Server 只校验 `identity` 字段结构和大小，转发 opaque identity object；不验证证书，不参与密钥协商语义。

## 与 WSS 的关系

WSS、mTLS 和 PKI 解决的问题不同：

- WSS 保护 Host/Client 到 Server 的传输通道，防止网络路径上的被动监听和主动篡改；
- mTLS 在反向代理入口要求客户端 TLS 证书，用于限制谁能建立到 Server 的连接；
- PKI 成员身份认证把成员证书签名绑定到 GKA v3 的临时 X25519 public key、成员 contribution 和 Host 的 `group_key`/group-state envelope；
- 即使使用 PKI，Server 仍能看到 room token、连接 id、成员状态、消息大小和转发时序等元数据；
- 即使使用 WSS，恶意 Server 仍可能尝试替换成员 public key，但 Host/Client 的 PKI 签名验证会拒绝不一致的 identity。

## Server 不验证哪一种证书

本文档中的 PKI 证书指的是应用层成员身份证书，也就是 `join_room.identity.certChainPem`、GKA contribution identity 和 `group_key.identity.certChainPem` 携带的证书链。Server 对这些证书只做 JSON 字段存在性、字段名、类型和大小检查，然后转发给 Host/Client。Server 不验证：

- 证书链是否由受信任 Root CA 签发；
- 证书是否过期；
- 证书 Key Usage 是否允许 `digitalSignature`；
- 证书是否出现在本地吊销列表；
- `join_room`、GKA contribution 或 `group_key` 的 identity 签名是否正确。

这些验证都发生在 Host/Client 本地。这样设计的原因是 Server 是不可信 relay，不能成为成员身份语义的信任根。mTLS 使用的客户端 TLS 证书是另一层连接准入证书，由 Nginx 等反向代理在 TLS 握手阶段验证，不是这里的应用层成员身份证书。

## 成员 id 命名

当前实现中有三个相关命名：

- `clientId`：Server 分配给普通 Client 的连接成员 id。
- `actorId`：加密消息 payload 中的稳定发送者 id，覆盖 Host 和 Client；Host 的 actor id 固定为 `host`。
- `memberId`：`member_identity` 控制消息和 WinUI UI 层使用的通用成员 id，值可以是 Host 的 `host`，也可以是普通 Client 的 `clientId`。

因此 `memberId` 存在于当前代码和协议控制消息中，但它不是 Server 内部唯一命名。Server 内部仍以 `clientId` 表示普通 Client，以固定 `host` 表示 Host。
