# SecureChat 环境变量参考

本文档列出当前仍可配置的 `SECURECHAT_*` 环境变量。不是每个运行角色都需要配置所有变量；Server、Host、Client 和 Nginx TLS 反向代理 backend 场景各自使用其中一部分。交互使用时优先通过命令参数、隐藏输入和脚本默认值完成，不建议把秘密长期写入 shell 启动文件。当前 Host/Client 必须配置 PKI 成员身份变量，否则会启动失败。

## 总览

当前共有 28 个 `SECURECHAT_*` 变量：

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
| `SECURECHAT_BIND_ADDRESS` | `0.0.0.0` | Server 绑定地址；Nginx TLS 反向代理 backend 建议设为 `127.0.0.1`。 |
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
| `SECURECHAT_TLS_CA_FILE` | 空 | Host/Client 使用的自定义 CA PEM 路径；用于信任自签名或私有 CA 签发的 WSS 入口证书。 |

`ws://` 是明文 WebSocket；公网部署建议使用 `wss://`。

## PKI 成员身份认证

PKI 是 Host/Client 必需配置。不配置完整变量时，Host/Client 启动失败；Server 不使用这些变量，仍只负责监听、房间注册、成员状态和密文 relay。

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
