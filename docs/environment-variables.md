# SecureChat 环境变量参考

本文档列出当前仍可配置的 `SECURECHAT_*` 环境变量。不是每个运行角色都需要配置所有变量；Server、Host、Client 和 Nginx TLS 反向代理 backend 场景各自使用其中一部分。CLI Host/Client 的成员 PKI 和 room instance token 从 `--room-dir` 指向的房间证书目录读取；WinUI 会自动创建或导入该目录，不要求用户手工填写路径。

## 总览

当前共有 14 个 `SECURECHAT_*` 变量：

```text
SECURECHAT_ALLOW_ROOT
SECURECHAT_ATTACHMENT_MAX_BYTES
SECURECHAT_BIND_ADDRESS
SECURECHAT_LOGS_MAX_BYTES
SECURECHAT_PORT
SECURECHAT_SERVER_BIN
SECURECHAT_SERVER_LOG_ENABLED
SECURECHAT_SERVER_PID_FILE
SECURECHAT_SERVER_STATE_DB
SECURECHAT_TLS_AUTO_DIR
SECURECHAT_LOCAL_TLS_CA
SECURECHAT_TLS_CERT_FILE
SECURECHAT_TLS_KEY_FILE
SECURECHAT_TLS_KEY_PASS
```

## Server 运行

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_SERVER_BIN` | `./out/build/x64-linux-release/server` | `start_server.sh` 使用的 Server 可执行文件路径。 |
| `SECURECHAT_PORT` | `25566` | Server 监听端口；`stop_server.sh` 也用它查找监听进程。 |
| `SECURECHAT_BIND_ADDRESS` | `0.0.0.0` | Server 绑定地址；Nginx TLS 反向代理 backend 建议设为 `127.0.0.1`。 |
| `SECURECHAT_SERVER_PID_FILE` | `server.pid` | Server daemon pid 文件路径。 |
| `SECURECHAT_SERVER_LOG_ENABLED` | `1` | `start_server.sh` 的 Server 日志输出开关；默认写入 `server/logs/server.log`，设为 `0` 时写入 `/dev/null`。 |
| `SECURECHAT_SERVER_STATE_DB` | `server/state/server-state.sqlite3` | Server 房间状态 SQLite 路径；保存 open/closed room instance 和 pending join 队列，不保存聊天明文或密钥。 |
| `SECURECHAT_ALLOW_ROOT` | 空 | `start_server.sh` 默认拒绝 root 运行；临时诊断时设为 `1` 才允许 root。 |

## WSS/TLS

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SECURECHAT_TLS_CERT_FILE` | 空 | TLS 证书链 PEM 路径。手动运行 `server` 时可留空，C++ Server 会自动生成本地/局域网证书；`start_server.sh` 未设置时会填入 `certs/fullchain.pem`。 |
| `SECURECHAT_TLS_KEY_FILE` | 空 | TLS 私钥 PEM 路径。手动运行 `server` 时可留空，C++ Server 会自动生成本地/局域网私钥；`start_server.sh` 未设置时会填入 `certs/privkey.pem`。 |
| `SECURECHAT_TLS_KEY_PASS` | 空 | TLS 私钥密码；只有私钥加密时需要。 |
| `SECURECHAT_LOCAL_TLS_CA` | 空 | Host/Client/WinUI 使用的本地服务器 CA PEM 路径；用于信任自动生成的本地或局域网 WSS 入口证书。 |
| `SECURECHAT_TLS_AUTO_DIR` | `certs` | 手动运行 `server` 且 TLS 路径环境变量为空时，C++ Server 自动生成本地/局域网 TLS 材料的目录。 |

`ws://` 明文 WebSocket 已禁用；Host/Client/WinUI 的 Server URL 必须使用 `wss://`。

## 房间级成员身份

Host/Client 不再读取全局成员 PKI 环境变量。CLI 的成员 trust store、成员证书链、成员私钥和 room instance token 都来自 `cert.exe` 生成或导入的房间证书目录，并通过 Host/Client 的 `--room-dir <dir>` 参数传入。WinUI 隐藏该路径，Host 启动时自动生成 `entrance.scp`，Client 加入时通过文件选择器导入 `entrance.scp`。成员私钥带口令时使用 CLI `--key-pass <pass>` 或 WinUI 设置面板中的成员私钥口令。

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
