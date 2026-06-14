# SecureChat 部署加固

本文档用于收尾阶段 5 到阶段 8 中仓库侧可以交付的部署安全工作：非 root 运行、来源 IP 收敛、临时日志清理、SIGTERM 优雅关闭验证，以及可选 systemd 服务模板。这里的措施只提升运行卫生和可用性，不替代 WSS 或应用层 E2EE。

## 推荐 Server 用户

公网 Server 建议使用专用低权限用户运行：

```bash
sudo useradd --system --create-home --home-dir /opt/SecureChat --shell /usr/sbin/nologin securechat
sudo mkdir -p /opt/SecureChat
sudo chown -R securechat:securechat /opt/SecureChat
```

把仓库部署到 `/opt/SecureChat` 后，以该用户构建或复制已经构建好的产物，并保持目录归属：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && ./build.sh'
```

`start_server.sh` 默认拒绝 root 运行。只有临时诊断时才设置 `SECURECHAT_ALLOW_ROOT=1`，不要把它作为常规部署方式。

## 手动 daemon 模式

手动 daemon 模式默认不保存日志：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && ./start_server.sh --mode wss'
```

停止并验证端口释放：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && ./stop_server.sh'
ss -lntp | grep ':25566' || echo '25566 released'
```

临时排障时显式启用日志，排障后删除：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && SECURECHAT_SERVER_LOG_FILE=server.log ./start_server.sh --mode wss'
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && ./stop_server.sh && rm -f server.log host.log client.log'
```

## 可选 systemd 服务

`deploy/securechat-server.service` 是可选 systemd 模板。systemd 是 Linux 的服务管理器，可以负责开机启动、停止服务、失败自动重启、限制运行用户和部分文件系统权限。它不是 SecureChat 协议的一部分，也不提供通信加密。`deploy/` 里的文件是 Linux 配置模板，不是双击运行的程序；使用前要复制到系统配置目录，并按实际路径、用户和证书位置调整。

使用前需要把仓库部署到 `/opt/SecureChat`，并把证书放在 `/opt/SecureChat/certs`：

```bash
sudo cp /opt/SecureChat/deploy/securechat-server.service /etc/systemd/system/securechat-server.service
sudo systemctl edit --full securechat-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now securechat-server.service
sudo systemctl status securechat-server.service
```

验证 SIGTERM/停止流程：

```bash
sudo systemctl stop securechat-server.service
ss -lntp | grep ':25566' || echo '25566 released'
```

模板包含 `Restart=on-failure`、`RestartSec=3`、`NoNewPrivileges=true`，并使用专用 `securechat` 用户。systemd 只改善进程监督和权限边界，不能替代 WSS 或应用层 E2EE。

## 可选 Nginx TLS 反向代理

Nginx 可以作为公网 TLS 入口，SecureChat Server 只监听本机 backend：

```text
Host/Client -- WSS --> Nginx :25566 -- local WS --> SecureChat Server 127.0.0.1:25567
```

这种模式下，Nginx 负责 TLS 终止和 WebSocket upgrade。SecureChat Server 只监听本机地址，继续负责房间注册、成员状态和 encrypted relay。

### 安装 Nginx

Nginx 是系统组件，需要先安装到服务器上。它不是本仓库自带的可执行文件。

Ubuntu/Debian 示例：

```bash
sudo apt update
sudo apt install -y nginx openssl
sudo systemctl enable --now nginx
```

RHEL/CentOS/openEuler 示例：

```bash
sudo dnf install -y nginx openssl
sudo systemctl enable --now nginx
```

安装后确认：

```bash
nginx -v
systemctl status nginx --no-pager
```

### 准备证书

| 类型 | 放在哪里 | 谁使用 | 作用 |
| --- | --- | --- | --- |
| 服务器 TLS 证书 | `/opt/SecureChat/certs/fullchain.pem`、`/opt/SecureChat/certs/privkey.pem` | Nginx | 证明 `wss://chat.la5te2.online:25566` 是正确服务器，并加密外部 TLS 通道。 |
| 应用层成员 PKI 证书 | `SECURECHAT_IDENTITY_CERT_FILE`、`SECURECHAT_IDENTITY_KEY_FILE` | SecureChat Host/Client 本地验签 | 绑定成员身份、临时 X25519 public key、GKA contribution 和 group state。 |

服务器 TLS 证书可以用 Let's Encrypt/Certbot 获取，步骤见 `docs/certificate_methods.md`。如果已有云厂商或其他 CA 签发的 PEM 证书，也可以直接放到上述路径。

如果 Nginx 的服务器 TLS 证书不是系统默认信任 CA 签发的，再额外设置：

```bash
export SECURECHAT_TLS_CA_FILE=certs/pki/root-ca.pem
```

复制模板：

```bash
sudo cp /opt/SecureChat/deploy/securechat-nginx-tls.conf /etc/nginx/conf.d/securechat-tls.conf
sudo editor /etc/nginx/conf.d/securechat-tls.conf
sudo nginx -t
sudo systemctl reload nginx
```

### 不使用 systemd 启动 backend

如果不想安装 SecureChat 的 systemd service，可以直接用项目脚本启动 backend。`start_server.sh` 默认会把 Server 放到后台运行；这里把 backend 绑定到 `127.0.0.1:25567`，公网只能通过 Nginx 的 `25566` 进入。

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && \
  SECURECHAT_BIND_ADDRESS=127.0.0.1 \
  SECURECHAT_PORT=25567 \
  SECURECHAT_SERVER_PID_FILE=server-backend.pid \
  ./start_server.sh --mode ws'
```

停止 backend：

```bash
sudo -u securechat -H bash -lc 'cd /opt/SecureChat && \
  SECURECHAT_PORT=25567 \
  SECURECHAT_SERVER_PID_FILE=server-backend.pid \
  ./stop_server.sh'
```

如果系统没有 systemd，Nginx 也可以直接用自身命令管理：

```bash
sudo nginx -t
sudo nginx
sudo nginx -s reload
sudo nginx -s quit
```

如果系统有 systemd，只是不想给 SecureChat backend 配 service，仍可以用 `sudo systemctl reload nginx` 管理 Nginx。

### 使用 systemd 启动 backend

使用 systemd 时复制 backend 模板：

```bash
sudo cp /opt/SecureChat/deploy/securechat-server-backend.service /etc/systemd/system/securechat-server-backend.service
sudo systemctl edit --full securechat-server-backend.service
sudo systemctl daemon-reload
sudo systemctl enable --now securechat-server-backend.service
```

验证监听面：

```bash
ss -lntp | grep -E ':(25566|25567)'
```

预期现象：

- `25566` 由 Nginx 对公网监听；
- `25567` 只绑定 `127.0.0.1`；
- Host/Client 通过 `wss://chat.la5te2.online:25566` 完成 WebSocket upgrade；
- 聊天内容仍由应用层 GKA v3/AES-256-GCM 保护，TLS 不替代成员身份 PKI。

如果 `chat.la5te2.online` 的服务器证书由私有 CA 或自签名证书签发，再额外设置：

```bash
export SECURECHAT_TLS_CA_FILE=certs/pki/root-ca.pem
```

## 网络暴露面

当前聊天只需要开放 Server WebSocket 端口：

```text
TCP 25566
```

不要把 Web UI 端口 `5188` 直接暴露到公网。Web UI 推荐绑定 `127.0.0.1`，或通过 SSH 隧道访问。

在华为云或其他云平台上，如果成员公网 IP 固定，安全组来源应尽量限制为这些 IP。若演示时成员 IP 不固定，才临时使用 `0.0.0.0/0`，并在文档或报告中说明原因，同时依赖 WSS、房间密码、限速和防火墙监控降低风险。

本机 UFW 示例：

```bash
sudo ufw allow from <trusted-client-ip>/32 to any port 25566 proto tcp
sudo ufw deny 25566/tcp
sudo ufw status numbered
```

演示场景需要公网开放时：

```bash
sudo ufw allow 25566/tcp
```

## 本地秘密输入卫生

Host 和 Client 的房间密码优先使用隐藏输入。非交互 daemon 模式优先用 stdin：

```bash
printf '%s\n' 'room-password' | ./start_host.sh --server wss://chat.la5te2.online:25566 --daemon
```

不要把房间密码写入 shell history、`.bashrc`、截图或长期日志。如果误写入 bash 历史，可用 `history -d <line>` 删除对应行。

## 运行痕迹

接收附件会被解密到本地缓存目录：

```text
logs/images
logs/voice
logs/files
```

程序会尽量设置 owner-only 权限并执行缓存大小限制，但部署者仍应定期删除不需要的文件：

```bash
find /opt/SecureChat/logs -type f -mtime +7 -delete
```
