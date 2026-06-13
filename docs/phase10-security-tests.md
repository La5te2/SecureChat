# SecureChat 阶段 10 安全测试记录

本文档用于阶段 10：敌手测试和显式安全性验证。所有测试只在本地环境、受控实验网络或自己控制的云服务器上执行。

## 已完成的本机验证

### 构建验证

已执行：

```powershell
.\build_win.bat
.\build_web.bat
```

预期和实际结果：

- C++ `server.exe`、`host.exe`、`client.exe`、`native.dll` 构建通过；
- WinUI 构建通过；
- Web UI 构建通过；
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

### mTLS 可实现性检查

已检查 libdatachannel 头文件：

- `rtc::WebSocketServer::Configuration` 支持 `enableTls`、`certificatePemFile`、`keyPemFile`、`keyPemPass`；
- 服务端配置没有 TLS 客户端证书验证、客户端 CA trust store 或 verify callback 字段；
- 因此 mTLS 由 Nginx 反向代理实现，SecureChat Server 作为 `127.0.0.1` backend。

仓库已提供：

- `SECURECHAT_BIND_ADDRESS`；
- `SECURECHAT_TLS_CA_FILE`；
- `SECURECHAT_MTLS_CLIENT_CERT_FILE`；
- `SECURECHAT_MTLS_CLIENT_KEY_FILE`；
- `SECURECHAT_MTLS_CLIENT_KEY_PASS`；
- `deploy/securechat-nginx-mtls.conf`；
- `deploy/securechat-server-mtls-backend.service`。

## 手动实验 1：WS 明文信令抓包

目的：证明 `ws://` 模式下信令明文可见，但应用层消息和附件内容仍是 encrypted relay。

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

## 手动实验 3：mTLS 连接准入

目的：证明没有客户端 TLS 证书时不能连接，有受信任客户端证书时可以连接。

### 部署步骤

启动 backend：

```bash
cd /opt/SecureChat
SECURECHAT_BIND_ADDRESS=127.0.0.1 SECURECHAT_PORT=25567 ./start_server.sh --mode ws
```

安装 Nginx mTLS 配置：

```bash
sudo cp /opt/SecureChat/deploy/securechat-nginx-mtls.conf /etc/nginx/conf.d/securechat-mtls.conf
sudo nginx -t
sudo systemctl reload nginx
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

### 无客户端证书测试

```bash
openssl s_client -connect chat.la5te2.online:25566 -servername chat.la5te2.online
```

预期现象：

- TLS 握手失败，或连接建立后被 Nginx 拒绝；
- Nginx error log 中出现 client certificate required 或 verify failed；
- Host/Client 无法完成 WebSocket 连接。

### 带客户端证书测试

```bash
openssl s_client \
  -connect chat.la5te2.online:25566 \
  -servername chat.la5te2.online \
  -cert certs/pki/alice-chain.pem \
  -key certs/pki/alice-key.pem
```

如果入口服务器证书由私有 CA 或自签名证书签发，再加 `-CAfile certs/pki/root-ca.pem`。

预期现象：

- TLS verify return code 为 0；
- 可以继续由 Host/Client 使用 `wss://chat.la5te2.online:25566` 建立 WebSocket；
- SecureChat Server 日志只看到来自本机代理的连接。

SecureChat Host/Client 连接 mTLS 入口：

```bash
export SECURECHAT_MTLS_CLIENT_CERT_FILE=certs/pki/alice-chain.pem
export SECURECHAT_MTLS_CLIENT_KEY_FILE=certs/pki/alice-key.pem
./start_client.sh --server wss://chat.la5te2.online:25566
```

如果入口服务器证书由私有 CA 或自签名证书签发，再设置 `SECURECHAT_TLS_CA_FILE=certs/pki/root-ca.pem`。

截图建议：

- `ss -lntp` 显示监听分离；
- 无证书失败；
- 有证书成功；
- Nginx 日志中的证书验证结果。

## 手动实验 4：PKI public key 替换验证

目的：证明启用 PKI 后，篡改 `join_room.publicKey` 会被 Host 拒绝。

### 步骤

1. 按 `docs/pki-identity.md` 生成 Root CA 和成员证书。
2. Host/Client 均设置：
   ```bash
   export SECURECHAT_PKI_TRUST_STORE=certs/pki/root-ca.pem
   export SECURECHAT_IDENTITY_CERT_FILE=certs/pki/alice-chain.pem
   export SECURECHAT_IDENTITY_KEY_FILE=certs/pki/alice-key.pem
   ```
3. 用受控代理或修改版测试 Server 把 `new_client.publicKey` 替换成另一个 X25519 public key，但保留原 `identity`。
4. 观察 Host 和 Client 输出。

### 预期现象

- Host 输出 `Client identity rejected` 或 `join_room identity signature verification failed`；
- Server 收到 `reject_client` 并断开目标 Client；
- Client 无法收到可用 room group key。

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

## 手动实验 6：附件安全

目的：验证附件大小、类型、文件头、路径净化和缓存上限。

### 步骤和预期现象

- 发送超过 `SECURECHAT_ATTACHMENT_MAX_BYTES` 的文件：发送端拒绝；
- 把文本文件改名为 `.png` 后用 `/image` 发送：文件头校验失败；
- 把非 WAV 文件改名为 `.wav` 后用 `/voice` 发送：RIFF/WAVE 校验失败；
- 发送名为 `../../evil.txt` 的附件：接收端文件名被净化，只落在 `logs/files`；
- 设置 `SECURECHAT_LOGS_MAX_BYTES=1048576` 后连续发送多个附件：缓存目录清理旧文件或拒绝新附件。

截图建议：

- 拒绝提示；
- 接收端最终保存路径；
- 缓存清理前后目录大小。

## 结论记录模板

每个实验建议记录：

1. 实验名称；
2. 敌手能力；
3. 执行环境；
4. 命令和截图；
5. 实际现象；
6. 安全结论；
7. 剩余风险。
