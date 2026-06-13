# SecureChat 环境变量参考

本文档列出当前仍可配置的 `SECURECHAT_*` 环境变量。它们都是可选项；交互使用时优先通过命令参数、隐藏输入和脚本默认值完成，不建议把秘密长期写入 shell 启动文件。

## 总览

当前共有 31 个 `SECURECHAT_*` 变量：

```text
SECURECHAT_ALLOW_ROOT
SECURECHAT_ATTACHMENT_MAX_BYTES
SECURECHAT_BIND_ADDRESS
SECURECHAT_CLIENT_BIN
SECURECHAT_CLIENT_LOG_FILE
SECURECHAT_CLIENT_PID_FILE
SECURECHAT_HOST_BIN
SECURECHAT_IDENTITY_CERT_FILE
SECURECHAT_IDENTITY_KEY_FILE
SECURECHAT_IDENTITY_KEY_PASS
SECURECHAT_LOG_FILE
SECURECHAT_LOGS_MAX_BYTES
SECURECHAT_MTLS_CLIENT_CERT_FILE
SECURECHAT_MTLS_CLIENT_KEY_FILE
SECURECHAT_MTLS_CLIENT_KEY_PASS
SECURECHAT_PID_FILE
SECURECHAT_PKI_REVOCATION_FILE
SECURECHAT_PKI_TRUST_STORE
SECURECHAT_PORT
SECURECHAT_ROOM
SECURECHAT_ROOM_PASSWORD
SECURECHAT_SERVER_BIN
SECURECHAT_SERVER_LOG_FILE
SECURECHAT_SERVER_PID_FILE
SECURECHAT_SERVER_URL
SECURECHAT_SIGNALING_TLS
SECURECHAT_TLS_CA_FILE
SECURECHAT_TLS_CERT_FILE
SECURECHAT_TLS_KEY_FILE
SECURECHAT_TLS_KEY_PASS
SECURECHAT_USER
```

## Server 运行

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_SERVER_BIN` | `./out/build/x64-linux-release/server` | `start_server.sh` 使用的 Server 可执行文件路径。 |
| `SECURECHAT_PORT` | `25566` | Server 监听端口；也用于 stop 脚本查找监听进程。 |
| `SECURECHAT_BIND_ADDRESS` | `0.0.0.0` | Server 绑定地址；mTLS 反向代理后端建议设为 `127.0.0.1`。 |
| `SECURECHAT_SERVER_PID_FILE` | `server.pid` | Server daemon pid 文件路径。 |
| `SECURECHAT_SERVER_LOG_FILE` | 空 | Server 诊断日志路径；为空时 daemon 输出写入 `/dev/null`。 |
| `SECURECHAT_ALLOW_ROOT` | 空 | `start_server.sh` 默认拒绝 root 运行；临时诊断时设为 `1` 才允许 root。 |

## Host 运行

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_HOST_BIN` | `./out/build/x64-linux-release/host` | `start_host.sh` 使用的 Host 可执行文件路径。 |
| `SECURECHAT_SERVER_URL` | `ws://127.0.0.1:25566` | Host/Client 默认连接的 Server URL。 |
| `SECURECHAT_ROOM` | `secure-room` | Host 创建或 Client 加入的默认 roomId。 |
| `SECURECHAT_USER` | Host 默认 `host`，Client 默认 `user1` | Host/Client 默认用户名。 |
| `SECURECHAT_PID_FILE` | `host.pid` | Host daemon pid 文件路径。 |
| `SECURECHAT_LOG_FILE` | 空 | Host 诊断日志路径；为空时 daemon 输出写入 `/dev/null`。 |

## Client 运行

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_CLIENT_BIN` | `./out/build/x64-linux-release/client` | `start_client.sh` 使用的 Client 可执行文件路径。 |
| `SECURECHAT_CLIENT_PID_FILE` | `client.pid` | Client daemon pid 文件路径。 |
| `SECURECHAT_CLIENT_LOG_FILE` | 空 | Client 诊断日志路径；为空时 daemon 输出写入 `/dev/null`。 |

Client 也会使用 `SECURECHAT_SERVER_URL`、`SECURECHAT_ROOM` 和 `SECURECHAT_USER`。

## 房间密码

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_ROOM_PASSWORD` | 空 | Host/Client 非交互自动化时的房间密码来源。 |

交互使用时不推荐设置 `SECURECHAT_ROOM_PASSWORD`。Host/Client CLI 会优先使用隐藏输入；daemon 自动化更推荐用 stdin：

```bash
printf '%s\n' 'room-password' | ./start_client.sh --server wss://chat.la5te2.online:25566 --daemon
```

脚本会尽量避免把 `SECURECHAT_ROOM_PASSWORD` 传入子进程环境。

## WSS/TLS

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_SIGNALING_TLS` | 空 | 设为 `1`、`true`、`TRUE`、`yes` 或 `on` 时启用 WSS。 |
| `SECURECHAT_TLS_CERT_FILE` | `start_server.sh --mode wss` 时默认为 `certs/fullchain.pem` | TLS 证书链 PEM 路径。 |
| `SECURECHAT_TLS_KEY_FILE` | `start_server.sh --mode wss` 时默认为 `certs/privkey.pem` | TLS 私钥 PEM 路径。 |
| `SECURECHAT_TLS_KEY_PASS` | 空 | TLS 私钥密码；只有私钥加密时需要。 |
| `SECURECHAT_TLS_CA_FILE` | 空 | Host/Client 使用的自定义 CA PEM 路径；用于信任自签名或私有 CA 签发的 WSS/mTLS 入口证书。 |

`ws://` 是明文 WebSocket；公网部署建议使用 `wss://`。

## mTLS 客户端证书

mTLS 服务端验证由 Nginx 反向代理完成。Host/Client 需要在 TLS 握手时出示客户端证书时，配置以下变量：

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_MTLS_CLIENT_CERT_FILE` | 空 | Host/Client 在 TLS 握手中出示的客户端证书链 PEM 路径。 |
| `SECURECHAT_MTLS_CLIENT_KEY_FILE` | 空 | Host/Client mTLS 客户端证书对应的私钥 PEM 路径。 |
| `SECURECHAT_MTLS_CLIENT_KEY_PASS` | 空 | mTLS 客户端私钥密码；只有私钥加密时需要。 |

示例：

```bash
export SECURECHAT_MTLS_CLIENT_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_MTLS_CLIENT_KEY_FILE=certs/pki/alice-key.pem
```

如果 WSS/mTLS 入口服务器证书由私有 CA 或自签名证书签发，再额外设置 `SECURECHAT_TLS_CA_FILE`。使用 Let's Encrypt 等系统已信任 CA 时通常不需要设置。

mTLS 负责连接准入；PKI 成员身份认证负责把成员身份签名绑定到 GKA v2 的临时 X25519 public key。两者可以使用同一套测试证书，但真实部署中建议按用途签发不同证书。

## PKI 成员身份认证

PKI 是可选模式。不配置这些变量时，Host/Client 仍按房间密码 + GKA v2 工作。只要配置了任一 PKI 变量，就必须同时提供信任根、成员证书链和成员私钥。

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_PKI_TRUST_STORE` | 空 | 受信任 CA bundle PEM 路径，用于验证 Host/Client 成员身份签名证书链。 |
| `SECURECHAT_IDENTITY_CERT_FILE` | 空 | 本机成员身份 PEM 证书链路径；Client 用它签名 `join_room`，Host 用它签名 `group_key`。 |
| `SECURECHAT_IDENTITY_KEY_FILE` | 空 | 本机成员身份私钥 PEM 路径。 |
| `SECURECHAT_IDENTITY_KEY_PASS` | 空 | 成员身份私钥密码；只有私钥加密时需要。 |
| `SECURECHAT_PKI_REVOCATION_FILE` | 空 | 本地受信任的 SHA-256 证书指纹吊销列表，每行一个指纹。 |

示例：

```bash
export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/member-chain.pem
export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/member-key.pem
export SECURECHAT_PKI_REVOCATION_FILE=certs/pki/revoked.txt
```

成员身份 PKI 的信令字段和验证流程见 `docs/pki-identity.md`。

## 附件

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_ATTACHMENT_MAX_BYTES` | `104857600` | 单个发送附件大小上限，默认 100 MB；图片、语音、文本附件共用同一个上限。 |
| `SECURECHAT_LOGS_MAX_BYTES` | `536870912` | 接收附件缓存总量上限，默认 512 MB。 |

示例：

```bash
export SECURECHAT_ATTACHMENT_MAX_BYTES=104857600
export SECURECHAT_LOGS_MAX_BYTES=1073741824
```

## 已移除的旧变量

当前不再使用 WebRTC/DataChannel/ICE/STUN，因此不再使用 `SECURECHAT_ICE_SERVERS`。当前也不再使用共享 E2EE passphrase，因此不再使用 `SECURECHAT_E2EE_PASSPHRASE`。
