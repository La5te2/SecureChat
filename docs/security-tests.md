# SecureChat 阶段 10 安全测试记录

本文档用于阶段 10：敌手测试和显式安全性验证。所有测试只在本地环境、受控实验网络或自己控制的云服务器上执行。

测试前的安装、编译、运行、PKI 和反向代理入口见 `README.md` 的“完整测试流程”；本文档记录阶段 10 需要执行或手动复现的安全实验步骤。

## 已完成的本机验证

### 构建验证

已执行：

```powershell
.\build_win.bat
```

预期和实际结果：

- C++ `server.exe`、`host.exe`、`client.exe`、`native.dll` 构建通过；
- WinUI 构建通过；
- 构建输出为 `0 warning / 0 error`。

### 旧连接层和旧兼容表述扫描

已执行关键词扫描：

```powershell
rg -n "PeerConnection|DataChannel|offer|answer|ice|ICE|STUN|TURN|legacy|compat|SECURECHAT_ICE_SERVERS|SECURECHAT_E2EE_PASSPHRASE" include src app docs README.md todolist.md CMakeLists.txt
```

预期现象：

- 代码中没有 Host/Client WebRTC PeerConnection 或 DataChannel 建连逻辑；
- Server 不接受或转发 `offer`、`answer`、`ice`；
- 文档只在“已移除/不再需要”语境中提到 WebRTC、DataChannel、STUN 或 ICE；
- `SECURECHAT_E2EE_PASSPHRASE` 和 `SECURECHAT_ICE_SERVERS` 只作为已移除变量出现。

### Nginx TLS 反向代理检查

已检查 libdatachannel 头文件：

- `rtc::WebSocketServer::Configuration` 支持 `enableTls`、`certificatePemFile`、`keyPemFile`、`keyPemPass`；
- SecureChat Server 可以直接启用 WSS，也可以只监听 `127.0.0.1` 作为 Nginx backend。

仓库已提供：

- `SECURECHAT_BIND_ADDRESS`；
- `SECURECHAT_TLS_CA_FILE`。

## 手动实验 1：WS 明文信令抓包

目的：证明 `ws://` 模式下信令明文可见，但应用层消息和附件内容仍是加密中继消息。

### 步骤

Server：

```bash
cd /opt/SecureChat
./start_server.sh --mode ws
```

Host：

```bash
./start_host.sh --server ws://<server-ip>:25566
```

Client：

```bash
./start_client.sh --server ws://<server-ip>:25566
```

抓包：

```bash
sudo tcpdump -i any -s 0 -w securechat-ws.pcap tcp port 25566
```

Wireshark 过滤器：

```text
tcp.port == 25566
websocket
frame contains "join_room"
frame contains "encrypted_relay"
frame contains "group_key"
```

### 预期现象

- 可以看到 `create_room`、`join_room`、`roomId`、`username` 和房间密码；
- 可以看到 `encrypted_relay` 和 `group_key` 的 JSON 字段名、nonce、tag、ciphertext 长度；
- 搜索实际聊天文本关键词时没有命中；
- 搜索原始附件文件名、mime 或附件内容关键词时没有命中。

截图建议：

- Wireshark 中明文 `join_room` 字段；
- 同一抓包中 `encrypted_relay.ciphertext`；
- 搜索聊天关键词无结果。

## 手动实验 2：WSS 抓包对比

目的：证明 `wss://` 模式下网络路径只能看到 TLS record，不能直接读取 WebSocket JSON。

### 步骤

Server：

```bash
cd /opt/SecureChat
./start_server.sh --mode wss
```

Host/Client 连接：

```text
wss://chat.la5te2.online:25566
```

抓包：

```bash
sudo tcpdump -i any -s 0 -w securechat-wss.pcap tcp port 25566
```

Wireshark 过滤器：

```text
tcp.port == 25566
tls
frame contains "join_room"
frame contains "encrypted_relay"
```

### 预期现象

- 能看到 TCP 连接、TLS ClientHello/ServerHello、证书和 TLS Application Data；
- 不能直接看到 `join_room`、`roomId`、房间密码或 `encrypted_relay` JSON；
- 仍能看到连接 IP、端口、包大小、时间间隔等元数据。

截图建议：

- TLS 握手和证书；
- `frame contains "join_room"` 无结果；
- 包长度和时间序列。

## 手动实验 3：Nginx TLS 反向代理暴露面

目的：证明公网只暴露 Nginx TLS 入口，SecureChat backend 只监听本机地址，外部网络路径只能看到 TLS record。

### 部署步骤

启动 backend：

```bash
cd /opt/SecureChat
SECURECHAT_BIND_ADDRESS=127.0.0.1 SECURECHAT_PORT=25567 ./start_server.sh --mode ws
```

如果服务器还没有 Nginx，先安装：

```bash
sudo apt update
sudo apt install -y nginx openssl
sudo nginx -v
```

创建 Nginx TLS 配置 `/etc/nginx/conf.d/securechat-tls.conf`：

```nginx
server {
    listen 25566 ssl;
    server_name chat.la5te2.online;

    ssl_certificate     /etc/letsencrypt/live/chat.la5te2.online/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.la5te2.online/privkey.pem;

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

检查并加载 Nginx 配置：

```bash
sudo nginx -t
sudo nginx
sudo nginx -s reload
```

确认监听：

```bash
ss -lntp | grep -E ':(25566|25567)'
```

预期：

```text
0.0.0.0:25566 或 [::]:25566 由 nginx 监听
127.0.0.1:25567 由 SecureChat backend 监听
```

### TLS 入口测试

```bash
openssl s_client -connect chat.la5te2.online:25566 -servername chat.la5te2.online
```

预期现象：

- TLS verify return code 为 0；
- 可以继续由 Host/Client 使用 `wss://chat.la5te2.online:25566` 建立 WebSocket；
- SecureChat Server 日志只看到来自本机代理的连接。

SecureChat Host/Client 连接 TLS 入口：

```bash
./start_client.sh --server wss://chat.la5te2.online:25566
```

如果入口服务器证书由私有 CA 或自签名证书签发，再设置 `SECURECHAT_TLS_CA_FILE=certs/pki/root-ca.pem`。

截图建议：

- `ss -lntp` 显示监听分离；
- `openssl s_client` 显示服务器 TLS 证书；
- Wireshark/tcpdump 中只能看到 TLS record；
- Nginx access/error log 中的 WebSocket upgrade 结果。

## 手动实验 4：PKI public key 替换验证

目的：证明强制 PKI 下，篡改 `join_room.publicKey` 会被 Host 拒绝；篡改成员列表或 `member_identity` 中的 pairwise public key 会被 Client 拒绝。

### 步骤

1. 按 `docs/pki-identity.md` 生成 Root CA 和成员证书。
2. Host/Client 均设置：
   ```bash
   export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
   export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
   export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
   ```
3. 用受控代理或修改版测试 Server 把 `new_client.publicKey` 替换成另一个 X25519 public key，但保留原 `identity`。
4. 用受控测试 Server 把 `room_members.memberInfos[].publicKey` 替换成另一个 X25519 public key，但保留原 `identity`。
5. 用受控测试 Host 或代理把加密 `member_identity` 解开后重新封装为冲突 public key，或发送一个同 member id 但不同证书指纹的测试控制消息。
6. 观察 Host 和 Client 输出。

### 预期现象

- Host 输出 `Client identity rejected` 或 `join_room identity signature verification failed`；
- Server 收到 `reject_client` 并断开目标 Client；
- Client 无法收到可用 room group key。
- Client 对被替换的 `room_members` 或 `member_identity` 输出 member identity rejected，不把该 public key 写入 pairwise 目标缓存。
- 同一个 member id 的 public key 或证书指纹发生冲突时，Client 拒绝覆盖已有已验证映射。

## 手动实验 5：Server 读取明文失败

目的：证明 Server 日志或抓包中没有聊天文本和附件明文。

### 步骤

临时启用 Server 日志：

```bash
SECURECHAT_SERVER_LOG_FILE=server.log ./start_server.sh --mode wss
```

发送文本：

```text
secret-message-123
```

发送附件：

```text
secret-plan.txt
```

检查：

```bash
grep -R "secret-message-123\|secret-plan.txt" server.log logs || true
```

### 预期现象

- Server 日志不包含聊天文本；
- Server 日志不包含原始附件文件名；
- 接收成员本地缓存中可以看到解密后的附件，因为成员设备是信任边界。

## 手动实验 6A：房间治理和错误投递

目的：验证 Host 禁言、驱逐、当前房间证书封禁，以及恶意 Server 错误投递、重放时的诚实端行为。

### Host 管理步骤

1. 启动一个 Host 和至少一个 Client，确认成员列表只显示成员名。
2. Host 输入：
   ```text
   /silence <成员名或id>
   ```
3. 被禁言 Client 尝试发送文本、`/image`、`/file` 或 `/voice`。
4. Host 输入：
   ```text
   /unsilence <成员名或id>
   ```
5. Client 再次发送文本。
6. Host 输入：
   ```text
   /evict <成员名或id>
   ```
7. 使用同一成员证书尝试重新加入当前房间。
8. 使用修改版 Client 或调试断点让某个 Client 收到 `gka_request` 后不发送 `gka_contribution`，等待 10 秒。

### Host 管理预期现象

- 禁言期间 Client 收到 `member is silenced`，文本和附件都不会被其他成员收到；
- 解除禁言后 Client 可以继续发送；
- 驱逐后 Client WebSocket 被关闭，Host 发起新的 GKA epoch；
- 同一证书在当前房间生命周期内重新加入时，Host 输出 banned certificate 或 reject 相关提示，不分发 group key。
- 拒绝提交 GKA contribution 的 Client 超时后被 Host 自动驱逐；Host 输出 `GKA contribution timeout`，并只用剩余成员重新发起 epoch。

### 错误投递步骤

1. 使用受控测试 Server 或代理，把一条私发 `encrypted_relay` 额外投递给非目标 Client。
2. 使用受控测试 Server 或代理，对正确目标重放同一条 `encrypted_relay`。
3. 使用受控测试 Server 或代理，重放旧的 `group_key` envelope。
4. 使用受控测试 Server 或代理，给 Host 发送一个不存在的 `client_left`。
5. 使用受控测试 Server 或代理，给 Client 发送一个非入房阶段普通 `error`。

### 错误投递预期现象

- 非目标 Client 输出 dropped 相关提示，不显示私信正文；即使攻击端跳过外层 `relayTargetId` 检查，也不能解开内层 pairwise 密文；
- 正确目标对重复 `encrypted_relay` 输出 `Dropped replayed encrypted relay`，不重复展示消息或附件；
- Client 对旧 `group_key` 输出 stale/replayed 相关错误，不回滚到旧 room group key；
- Host 输出 `Ignored unknown client_left`，成员列表不变，不触发新的 group key rotation。
- Client 对非终止类中继错误只显示错误提示，不主动退出；入房失败和 `host disconnected` 仍是终止事件。

## 手动实验 6：附件安全

目的：验证附件大小、类型、文件头、路径净化和缓存上限。

### 步骤和预期现象

- 发送超过 `SECURECHAT_ATTACHMENT_MAX_BYTES` 的文件：发送端拒绝；
- 把文本文件改名为 `.png` 后用 `/image` 发送：文件头校验失败；
- 把非 WAV 文件改名为 `.wav` 后用 `/voice` 发送：RIFF/WAVE 校验失败；
- 发送名为 `../../evil.txt` 的附件：接收端文件名被净化，只落在 `logs/files`；
- 设置 `SECURECHAT_LOGS_MAX_BYTES=1048576` 后连续发送多个附件：缓存目录清理旧文件或拒绝新附件；
- WinUI 中发送者被右键标记为 Blocked 时接收图片/音频：界面只显示“附件已接收”，不会自动预览；
- WinUI 中 Allowed 成员接收图片：若“自动预览图片”开启，图片通过尺寸和像素校验后自动预览；
- WinUI 中接收异常大尺寸图片或异常 WAV：附件卡片存在，但点击预览时显示“预览已阻止”。

截图建议：

- 拒绝提示；
- 接收端最终保存路径；
- 缓存清理前后目录大小。

## 手动实验 7：端口扫描和 TCP 半连接

目的：验证公网部署只暴露必要端口，并说明 TCP 半连接攻击主要由系统、云安全组和反向代理层缓解。

### 端口扫描步骤

在授权测试机上扫描自己的服务器：

```bash
nmap -Pn -p 22,80,443,25566,25567 <your-server-ip-or-domain>
```

在服务器上对照监听和防火墙：

```bash
ss -lntp
sudo ufw status
```

### 端口扫描预期现象

- 公网 Server 部署只需要暴露 TCP `25566`。
- Nginx TLS 反向代理部署中，公网只暴露 Nginx `25566`，SecureChat backend `25567` 只监听 `127.0.0.1`。

### TCP 半连接步骤

只在自己控制的服务器上做低速、限量测试：

```bash
sysctl net.ipv4.tcp_syncookies
ss -ant state syn-recv
sudo nping --tcp -S -p 25566 --rate 10 -c 100 <your-server-ip-or-domain>
watch -n 1 "ss -ant state syn-recv | wc -l"
```

### TCP 半连接预期现象

- 低速、限量 SYN 测试不应导致正常 Host/Client 长时间不可用。
- 半连接防护主要来自 Linux TCP 栈、SYN cookies、云安全组、Nginx 和连接 backlog。
- SecureChat 应用层连接超时、连接数限制和坏消息限制只处理 WebSocket 建立之后的资源消耗。

## 结论记录模板

每个实验建议记录：

1. 实验名称；
2. 敌手能力；
3. 执行环境；
4. 命令和截图；
5. 实际现象；
6. 安全结论；
7. 剩余风险。
