# SecureChat PKI 成员身份认证

本文档说明当前已经实现的阶段 9：用成员身份签名证书绑定 GKA v2 中的临时 X25519 public key，降低恶意 Server 或主动中间人替换公钥的风险。

这里的 PKI 证书不是 WSS 服务器证书。WSS 服务器证书用于证明 `wss://chat.la5te2.online:25566` 连接到正确的 Server；成员身份证书用于证明某个 Host/Client 的 `join_room` 或 `group_key` envelope 由持有身份私钥的成员签名。

## 启用方式

PKI 是可选模式。不配置任何 PKI 变量时，Host/Client 仍按房间密码 + GKA v2 工作。只要配置了任一 PKI 变量，就必须同时提供信任根、成员证书链和成员私钥：

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

成员证书的 Key Usage 如果存在，必须允许 `digitalSignature`。代码不会用 X25519 做身份认证；X25519 只用于 ECDH 和 group key 封装，身份认证由证书里的签名公钥完成。

## 最小证书生成示例

下面示例适合本地实验。正式部署时，Root CA 私钥应离线保存，并用 Intermediate CA 签发成员证书。

生成测试 Root CA：

```bash
mkdir -p certs/pki
openssl genpkey -algorithm ED25519 -out certs/pki/root-ca-key.pem
openssl req -x509 -new -key certs/pki/root-ca-key.pem \
  -out certs/pki/root-ca.pem \
  -days 3650 \
  -subj "/CN=SecureChat Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

生成一个成员身份密钥和证书：

```bash
openssl genpkey -algorithm ED25519 -out certs/pki/alice-key.pem
openssl req -new -key certs/pki/alice-key.pem \
  -out certs/pki/alice.csr \
  -subj "/CN=alice"

cat > certs/pki/member.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req \
  -in certs/pki/alice.csr \
  -CA certs/pki/root-ca.pem \
  -CAkey certs/pki/root-ca-key.pem \
  -CAcreateserial \
  -out certs/pki/alice-chain.pem \
  -days 365 \
  -extfile certs/pki/member.ext
```

启动 Alice 这个成员时：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
```

查看证书 SHA-256 指纹：

```bash
openssl x509 -in certs/pki/alice-chain.pem -noout -fingerprint -sha256
```

需要吊销该证书时，把输出中的十六进制指纹写入 `SECURECHAT_PKI_REVOCATION_FILE` 指向的文本文件。

## join_room 绑定

Client 加入房间时仍会生成临时 X25519 key pair，并把 public key 放入 `join_room`。启用 PKI 后，Client 还会附带 `identity` 对象：

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

验证失败时，Host 发送 `reject_client`，Server 会移除该 Client 并关闭其 WebSocket。验证通过后，Host 才记录该 public key、轮换 room group key，并为该成员封装 group key。

## group_key 绑定

Host 给 Client 分发 group key 时，先按 GKA v2 生成 `group_key` envelope，再用 Host 身份私钥签名。签名覆盖：

```text
securechat-pki-v1
group_key
roomId:<len>:<roomId>
targetId:<len>:<clientId>
senderId:<len>:host
alg:<len>:AES-256-GCM
kdf:<len>:X25519-HKDF-SHA256
ephemeralPublicKey:<len>:<host-ephemeral-x25519-public-key>
nonce:<len>:<aes-gcm-nonce>
ciphertext:<len>:<wrapped-group-key>
tag:<len>:<aes-gcm-tag>
identityNonce:<len>:<identity-nonce>
```

Client 在解封装 group key 之前，会先验证 Host 证书链、吊销状态、签名算法和签名。如果验证失败，Client 不会执行 X25519 解封装，也不会接受该 room group key。

## 吊销列表

`SECURECHAT_PKI_REVOCATION_FILE` 是本地受信任文本文件，每行一个 SHA-256 证书指纹，大小写和冒号不敏感：

```text
# revoked.txt
9F:12:AB:...
7c32aa...
```

当前实现会检查 identity 证书链中的每张证书。如果叶子证书或中间证书的 SHA-256 指纹出现在吊销列表中，该 identity 会被拒绝。成员被拒绝或离开后，Host 的既有成员变化逻辑会轮换 room group key。

## 代码位置

- `include/identity_pki.hpp`：PKI 身份上下文接口。
- `src/identity_pki.cpp`：证书链验证、吊销检查、签名与验签。
- `src/client_session_core.cpp`：Client 在 `join_room` 中签名身份，并在收到 `group_key` 后验证 Host 身份。
- `src/host_session_core.cpp`：Host 验证 Client 身份，签名 `group_key`，并拒绝验证失败的 Client。
- `src/signaling_server.cpp`：Server 只校验 `identity` 字段结构和大小，转发 opaque identity object；不验证证书，不参与密钥协商语义。

## 与 WSS 的关系

WSS、mTLS 和 PKI 解决的问题不同：

- WSS 保护 Host/Client 到 Server 的传输通道，防止网络路径上的被动监听和主动篡改；
- mTLS 在反向代理入口要求客户端 TLS 证书，用于限制谁能建立到 Server 的连接；
- PKI 成员身份认证把成员证书签名绑定到 GKA v2 的临时 X25519 public key 和 Host 的 `group_key` envelope；
- 即使使用 PKI，Server 仍能看到 roomId、成员状态、消息大小和转发时序等元数据；
- 即使使用 WSS，如果不启用成员身份 PKI，恶意 Server 仍可能在应用层尝试替换成员 public key。
